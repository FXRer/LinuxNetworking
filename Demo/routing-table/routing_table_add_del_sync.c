#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
#include <sys/ioctl.h>
 
bool addNullRoute( long host )            
{ 
   // create the control socket.
   int fd = socket( PF_INET, SOCK_DGRAM, IPPROTO_IP );
 
   struct rtentry route;
   memset( &route, 0, sizeof( route ) );
 
   // set the gateway to 0.
   struct sockaddr_in *addr = (struct sockaddr_in *)&route.rt_gateway;
   addr->sin_family = AF_INET;
   addr->sin_addr.s_addr = 0;
 
   // set the host we are rejecting. 
   addr = (struct sockaddr_in*) &route.rt_dst;
   addr->sin_family = AF_INET;
   addr->sin_addr.s_addr = htonl(host);
 
   // Set the mask. In this case we are using 255.255.255.255, to block a single
   // IP. But you could use a less restrictive mask to block a range of IPs. 
   // To block and entire C block you would use 255.255.255.0, or 0x00FFFFFFF
   addr = (struct sockaddr_in*) &route.rt_genmask;
   addr->sin_family = AF_INET;
   addr->sin_addr.s_addr = 0xFFFFFFFF;
 
   // These flags mean: this route is created "up", or active
   // The blocked entity is a "host" as opposed to a "gateway"
   // The packets should be rejected. On BSD there is a flag RTF_BLACKHOLE
   // that causes packets to be dropped silently. We would use that if Linux
   // had it. RTF_REJECT will cause the network interface to signal that the 
   // packets are being actively rejected.
   route.rt_flags = RTF_UP | RTF_HOST | RTF_REJECT;
   route.rt_metric = 0;
 
   // this is where the magic happens..
   if ( ioctl( fd, SIOCADDRT, &route ) )
   {
      close( fd );
      return false;
   }
 
   // remember to close the socket lest you leak handles.
   close( fd );
   return true; 
}

bool delNullRoute( long host )            
{ 
   int fd = socket( PF_INET, SOCK_DGRAM, IPPROTO_IP );
 
   struct rtentry route;
   memset( &route, 0, sizeof( route ) );
 
   struct sockaddr_in *addr = (struct sockaddr_in *)&route.rt_gateway;
   addr->sin_family = AF_INET;
   addr->sin_addr.s_addr = 0;
 
   addr = (struct sockaddr_in*) &route.rt_dst;
   addr->sin_family = AF_INET;
   addr->sin_addr.s_addr = htonl(host);
 
   addr = (struct sockaddr_in*) &route.rt_genmask;
   addr->sin_family = AF_INET;
   addr->sin_addr.s_addr = 0xFFFFFFFF;
 
   route.rt_flags = RTF_UP | RTF_HOST | RTF_REJECT;
   route.rt_metric = 0;
 
   // this time we are deleting the route:
   if ( ioctl( fd, SIOCDELRT, &route ) )
   {
      close( fd );
      return false;
   }
 
   close( fd );
   return true; 
}

bool syncNullRoutes( const KxVector<long>& hostList ) 
{ 
   // hostlist contains the complete list of remote IPs we want to ban.
   // IPs on this list that are not already banned will get banned.
   // IPs that are banned that are not on this list will get unbanned.
 
   // read the route table from procfs. 
   KxTokBuf routeTable;
   KxfPath path( "/proc/net/route" );
   if ( !path.readFile( routeTable ))
   {
      return false;
   }
 
   KxVector<long> hl = hostList;
   KxVector<long> ex;
   hl.sort();
 
   // parse the route table to see which routes already exist.
   const char* line;
   KxTokBuf lineBuf;
   while (( line = routeTable.getToken( "\n", "\r\t " )))
   {
      // consider only rows that affect all interfaces, since our ban 
      // routes all work like that.
      if ( *line != '*' ) continue;
      lineBuf.tokenize( line + 1 );
 
      u32 vals[10];
      u32 idx = 0;
      const char* tok;
      while (( tok = lineBuf.getToken( " \t", " \t" )))
      {
         vals[idx++] = strtol( tok, NULL, 16 );
         if ( idx >= 10 ) break;
      }
 
      // at this point, each column in the row has been parsed into vals.
      // offset 2, is the flags field. Offset 0 is the remote IP. 
      if ( vals[2] == ( RTF_UP | RTF_HOST | RTF_REJECT ))
      {
         long ip = htonl( vals[0] );
         if ( hl.contains( ip ) )
         {
            // route exists in hostList, and in route table. Add to ex
            ex.insert( ip );
         } else {
            // route does not exist in hostList, remove from route table.
            delNullRoute( ip );
         }
      }
   }
 
   // add in all routes that don't exist in route table.
   ex.sort();
   for ( u32 i = 0; i < hl.size(); i++ )
   {
      long ip = hl[i];
      if ( ex.contains( ip ) )
         addNullRoute( ip );
   }
   return true; 
}

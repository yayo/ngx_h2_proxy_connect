
/*
gcc -Wall -Wextra -std=c++11 -lnghttp2_asio -lboost_system -lssl -lcrypto -lstdc++ -o test test.cpp

nghttpd -v --hexdump 3000 nghttpx.key nghttpx.crt

https://http2.github.io/faq/#can-i-implement-http2-without-implementing-http11

nghttp2_session_create_idle_stream
nghttp2_session_set_next_stream_id
nghttp2_on_data_chunk_recv_callback

dd if=/dev/urandom bs=1M of=a count=128
dd if=/dev/urandom bs=1M of=b count=1

/usr/bin/nghttpd -v --hexdump 3000 nghttpx.key nghttpx.crt

./test 127.0.0.1 3000 a b 

*/

#include <iostream>
#include <nghttp2/asio_http2_client.h>

void dump(uint8_t *d,uint8_t l)
{uint8_t i;
 for(i=0;i<l;i++) printf("%02x",d[i]);
}

int main(int argc,char *argv[])
 {if(5==argc)
   {boost::system::error_code ec;
    boost::asio::ssl::context tls(boost::asio::ssl::context::tlsv12);
    tls.set_default_verify_paths();
    nghttp2::asio_http2::client::configure_tls_context(ec,tls);
    boost::asio::io_service io_service;
    nghttp2::asio_http2::client::session s(io_service,tls,argv[1],argv[2]);
    s.on_connect
     ([&s,&argv](__attribute__((unused)) boost::asio::ip::tcp::resolver::iterator endpoint_it)
       {boost::system::error_code ec1;
        size_t *l1=new size_t(0);
        EVP_MD_CTX *c1=NULL;
        assert(NULL!=(c1=EVP_MD_CTX_create()));
        assert(1==EVP_DigestInit_ex(c1,EVP_get_digestbyname("md5"),NULL));
        size_t *n1=new size_t(0);
        timespec *t1a=new timespec({0,0});
        timespec *t1b=new timespec({0,0});
        timespec *t1c=new timespec({0,0});
        const nghttp2::asio_http2::client::request *r1;
        clock_gettime(CLOCK_REALTIME,t1a);
        r1=s.submit(ec1,"GET",std::string("http://")+argv[1]+":"+argv[2]+"/"+argv[3]);
        r1->on_response
         ([&s,&argv,l1,c1,n1,t1b,t1c](const nghttp2::asio_http2::client::response &res1)
           {clock_gettime(CLOCK_REALTIME,t1b);
            std::cerr<<"1HEAD= "<<res1.status_code()<<std::endl; for(const std::pair<std::string,nghttp2::asio_http2::header_value> &kv : res1.header()) {std::cerr<<kv.first<<": "<< kv.second.value<<"\n";} std::cerr << std::endl;

            res1.on_data
             ([&s,&argv,l1,c1,n1,t1c](const uint8_t *data,std::size_t len)
               {if(0==t1c->tv_sec) clock_gettime(CLOCK_REALTIME,t1c);
                *l1+=len;
                n1[0]++;
                EVP_DigestUpdate(c1,data,len);

                static uint8_t flag=0;
                if(0==flag)
                 {flag=1;
                  const nghttp2::asio_http2::client::request *r2;
                  boost::system::error_code ec2;
                  size_t *l2=new size_t(0);
                  EVP_MD_CTX *c2=NULL;
                  assert(NULL!=(c2=EVP_MD_CTX_create()));
                  assert(1==EVP_DigestInit_ex(c2,EVP_get_digestbyname("md5"),NULL));
                  size_t *n2=new size_t(0);
                  timespec *t2a=new timespec({0,0});
                  timespec *t2b=new timespec({0,0});
                  timespec *t2c=new timespec({0,0});
                  clock_gettime(CLOCK_REALTIME,t2a);
                  r2=s.submit(ec2,"GET",std::string("http://")+argv[1]+":"+argv[2]+"/"+argv[4]);
                  r2->on_response
                   ([l2,c2,n2,t2b,t2c](const nghttp2::asio_http2::client::response &res2)
                     {clock_gettime(CLOCK_REALTIME,t2b);
                      std::cerr<<"2HEAD= "<<res2.status_code()<<std::endl; for(const std::pair<std::string,nghttp2::asio_http2::header_value> &kv : res2.header()) {std::cerr<<kv.first<<": "<< kv.second.value<<"\n";} std::cerr << std::endl;
                      res2.on_data
                       ([l2,c2,n2,t2c](const uint8_t *data,std::size_t len)
                         {if(0==t2c->tv_sec) clock_gettime(CLOCK_REALTIME,t2c);
                          *l2+=len;
                          n2[0]++;
                          EVP_DigestUpdate(c2,data,len);
                         }
                       );
                     }
                   );
                  r2->on_close
                   ([&s,&argv,l2,c2,n2,t2a,t2b,t2c](uint32_t e)
                     {timespec t;
                      clock_gettime(CLOCK_REALTIME,&t);
                      unsigned char m[EVP_MAX_MD_SIZE];
                      EVP_DigestFinal_ex(c2,m,&e);
                      EVP_MD_CTX_destroy(c2);
                      fprintf(stdout,"2REQ=%010lu.%09lu HDR=%010lu.%09lu DAT=%010lu.%09lu END=%010lu.%09lu MD5= ",t2a->tv_sec,t2a->tv_nsec,t2b->tv_sec,t2b->tv_nsec,t2c->tv_sec,t2c->tv_nsec,t.tv_sec,t.tv_nsec); dump(m,e); std::cout<<" SIZE="<<*l2<<" N="<<*n2<<std::endl;
                      delete l2;
                      delete n2;
                      delete t2a;
                      delete t2b;
                      delete t2c;
                      if(NULL==argv[0]) s.shutdown();
                      else argv[0]=NULL;
                     }
                   );
                 }
               }
             );
           }
         );
        r1->on_close
         ([&s,&argv,l1,c1,n1,t1a,t1b,t1c](uint32_t e)
           {timespec t;
            clock_gettime(CLOCK_REALTIME,&t);
            unsigned char m[EVP_MAX_MD_SIZE];
            EVP_DigestFinal_ex(c1,m,&e);
            EVP_MD_CTX_destroy(c1);
            fprintf(stdout,"1REQ=%010lu.%09lu HDR=%010lu.%09lu DAT=%010lu.%09lu END=%010lu.%09lu MD5= ",t1a->tv_sec,t1a->tv_nsec,t1b->tv_sec,t1b->tv_nsec,t1c->tv_sec,t1c->tv_nsec,t.tv_sec,t.tv_nsec); dump(m,e); std::cout<<" SIZE="<<*l1<<" N="<<*n1<<std::endl;
            delete l1;
            delete n1;
            delete t1a;
            delete t1b;
            delete t1c;
            if(NULL==argv[0]) s.shutdown();
            else argv[0]=NULL;
           }
         );
       }
     );
    s.on_error
     ([](const boost::system::error_code &ec)
       {std::cerr<<"error: "<<ec.message()<<std::endl;
       }
     );
    io_service.run();
   }
 }


= Smarta

smarta agent for linux/unix

= Build

./build.sh

= Install

0. install lua

tar xvf lua-5.1.4.tar.gz
cd lua-5.1.4
make linux && make install

1. login http://nodebus.com

2. register node, got name and apikey

3. configue smarta.conf 
    replace $NAME$ with name
    replace $APIKEY$ with apikey

4. start smarta:
    ./smarta smarta.conf

= Master/Slave

If your servers behind firewall and cannot access internet directly,
you could configure one smarta as master:
    smarta {
        master 7777
    }

others as slaves:
    smarta {
        slaveof MASTER_IP 7777
    }

= Credits

I seldom write c program, but i know what's the best. So smarta use redis event library to rewrite libstrope xmpp library.

= Plugins

1. check_disk check disk
2. check_memory check memory usage
3. check_swap check swap
4. check_process check process
5. check_log check logfile size
6. check_cpu  check cpu usage


= Smarta

smarta agent 0.4.2 for linux32

= Install lua

tar xvf lua-5.1.4.tar.gz
cd lua-5.1.4
make linux && make install

= Install smarta

1. login http://nodebus.com

2. register node, got name and apikey

3. configue smarta.conf 
    replace $NAME$ with name
    replace $APIKEY$ with apikey

4. start smarta:
    ./smarta smarta.conf

= Master/Slave

if your servers behind firewall and cannot access internet directly,
you could configure one smarta as master:
    smarta {
        master 7777
    }

others as slaves:
    smarta {
        slaveof MASTER_IP 7777
    }

= Plugins

1. check_disk 检查磁盘是否满了
2. check_memory 检查内存占用
3. check_swap 检查内存占用
4. check_process 检查进程正常吗
5. check_log 检查日志大小


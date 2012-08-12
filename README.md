DBENCH NFS Loadfiles
====================
dbench is a tool which can be used to generate I/O workloads to a networked NFS server.

Background
----------
The original nfsloadfile.sh shell script from the [dbench project][dbench] is used to generate a load file (used by dbench) from a wireshark packet capture of NFS traffic.

The latest version of this script can be downloaded from the dbench git repository on samba.org:

git clone git://git.samba.org/sahlberg/dbench.git dbench

The original shell script is Copyright (C) by Ronnie Sahlberg <sahlberg@samba.org> 2008.

What is this
-------------
This is a straight port of the aforementioned shell script to [Google's Go language][go]. It is also my first Go program. As such, I'm sure there are improvements which can be made. Feel free to suggest changes and/or fork/submit pull requests.

Compile
-------
go build nfsloadfile.go

Usage
-----
./nfsloadfile [nfs.cap][cap] > nfs.loadfile

License
-------
As a derivative work, this software is licensed under the GPL v3.

[dbench]:http://dbench.samba.org/
[go]:http://golang.org/
[cap]:http://dbench.samba.org/web/nfs.cap

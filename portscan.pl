#!/usr/bin/env perl

 ###########################################################################//*!
 # @mainpage PortScan                                                         #
 # @file     portscan.pl                                                      #
 # @author   alice <chaoticmurlock@gmail.com>                                 #
 # @version  1.0                                                              #
 # @date     19/10/2014                                                       #
 #                                                                            #
 # @brief    Simple port scanner.                                             #
 #                                                                            #
 # @section  LICENSE                                                          #
 # Copyright (c) 2014, alice                                                  #
 # All rights reserved.                                                       #
 #                                                                            #
 # Redistribution and use in source and binary forms, with or without         #
 # modification, are permitted provided that the following conditions         #
 # are met:                                                                   #
 # 1. Redistributions of source code must retain the above copyright          #
 #    notice, this list of conditions and the following disclaimer.           #
 # 2. Redistributions in binary form must reproduce the above copyright       #
 #    notice, this list of conditions and the following disclaimer in the     #
 #    documentation and/or other materials provided with the distribution.    #
 # 3. Neither the name of the University nor the names of its contributors    #
 #    may be used to endorse or promote products derived from this software   #
 #    without specific prior written permission.                              #
 #                                                                            #
 # THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND    #
 # ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE      #
 # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE #
 # ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE   #
 # FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL #
 # DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS    #
 # OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)      #
 # HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT #
 # LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY  #
 # OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF     #
 # SUCH DAMAGE.                                                               #
 #//##########################################################################*/

use strict;
use warnings;

use IO::Select;
use IO::Socket::INET;

sub quit_usage
{
    print "Usage : \n\t$0 [options] [target-specification] [port-range]\n";

    print "\n";

    print "[*] Options :\n";
    print "  - scan\t[default option] Scan most used ports.\n";
    print "  - fast\tScan first 100 most used ports.\n";
    print "  - discover\tDisable port scan.\n";
    print "  - stealth\tStealth scan. (Preferably used on known alive hosts)\n";

    exit(0);
}

quit_usage unless @ARGV > 0 and @ARGV < 4;

sub quit_error_ports   { print "Incorrect port specification.\n";    exit(1); }
sub quit_error_address { print "Incorrect address specification.\n"; exit(1); }
sub quit_error_options { print "Incorrect option.\n";                exit(1); }

my $ipsmplx;
my $ipcidrx;
my $iprangx;
my $ipranjx;

my $prtsmplx;
my $prtrangx;

my $optdscvx;
my $optstlhx;
my $optfastx;
my $optscanx;

my $opt = shift @ARGV;
my $adr = shift @ARGV;
my $prt = shift @ARGV;

my $pos = tell DATA;

sub sort_options
{
    my $ipallx;
    my $prtallx;
    my $optallx;

    my $byte = '(?:25[0-5]|2[0-4]\d|1?\d{1,2})';
    my $four = "(?:(?:$byte\\.){3}$byte)";
    my $cidr = "(?:$four\\/(?:3[0-2]|[1-2]?\\d))";
    my $rang = "(?:$byte(?:\\-$byte)?)(?:\\.$byte(?:\\-$byte)?){3}";
    my $ranj = "(?:$four\\-(?:$byte(?:\\.$byte){0,3}))";
    my $list = "(?:$four(?:,$four)+)";
    my $cplx = "(?:$four|$cidr|$rang|$ranj)(?:,(?:$four|$cidr|$rang|$ranj))+";

    $ipallx = qr/^(?:$four|$cidr|$rang|$ranj|$list|$cplx)$/;

    $ipsmplx = qr/^$four$/;
    $ipcidrx = qr/^$cidr$/;
    $iprangx = qr/^$rang$/;
    $ipranjx = qr/^$ranj$/;

   $byte='(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[0-5]\d{4}|\d{1,4})';
   $rang = "(?:$byte\\-$byte)";
   $list = "(?:$byte(?:,$byte)+)";
   $cplx = "(?:(?:$byte|$rang)(?:,(?:$byte|$rang))+)";

    $prtallx = qr/^(?:$byte|$rang|$list|$cplx)$/;

    $prtsmplx = qr/^$byte$/;
    $prtrangx = qr/^$rang$/;

    my $optdscv = '(?:d|D|discover|\-d|\-D|\-\-discover)';
    my $optstlh = '(?:s|S|stealth|\-s|\-S|\-\-stealth)';
    my $optscan = '(?:c|C|scan|\-c|\-C|\-\-scan)';
    my $optfast = '(?:f|F|fast|\-f|\-F|\-\-fast)';

    $optallx = qr/^(?:$optdscv|$optstlh|$optscan|$optfast)$/;

    $optdscvx = qr/^$optdscv$/;
    $optstlhx = qr/^$optstlh$/;
    $optscanx = qr/^$optscan$/;
    $optfastx = qr/^$optfast$/;

    ($opt,$adr) = ($adr,$opt) if defined $opt and $opt =~ $ipallx;
    ($prt,$adr) = ($adr,$prt) if defined $prt and $prt =~ $ipallx;
    ($adr,$prt) = ($prt,$adr) if defined $adr and $adr =~ $prtallx;
    ($opt,$prt) = ($prt,$opt) if defined $opt and $opt =~ $prtallx;
    ($prt,$opt) = ($opt,$prt) if defined $prt and $opt =~ $optallx;
    ($adr,$opt) = ($opt,$adr) if defined $adr and $adr =~ $optallx;

    $opt = "scan" unless defined $opt;

    quit_error_ports   unless ! defined $prt or  $prt =~ $prtallx;
    quit_error_address unless   defined $adr and $adr =~ $ipallx;
    quit_error_options unless   defined $opt or  $opt =~ $optallx;
}

sub discover_one
{
    my $ready;
    my $select = new IO::Select();

    my $socket = new IO::Socket::INET(Proto=>'udp',
                                      PeerAddr=>$_[0],
                                      PeerPort=>65432)
            or print "Please verify your internet connection.\n" and exit(-1);

    print $socket "Whisper whisper ..." and $select->add($socket);
    ($ready) = IO::Select->select($select,undef,undef,1);
    foreach(@$ready) { return 1 if $_ == $socket or last; }
    return 0;
}

sub scan_one
{
    my $socket = new IO::Socket::INET(Proto=>'tcp',
                                      PeerAddr=>$_[0],
                                      PeerPort=>$_[1])
                                 or return 0;
    $socket->shutdown(2);
    $socket->close();
    return 1;
}

sub scan_mul
{
    my @open;

    foreach my $port (split/\-/,$_[1]) {
        push@open,$port if scan_one $_[0],$port;
    }

    return @open;
}

sub discover
{
    my %a;

    foreach(split/,/,$_[0])
    {
        if   ($_ =~ $ipsmplx) { @{$a{$_}} = () if discover_one $_; }
        elsif($_ =~ $ipcidrx)
        {
            my ($sip,$eip) = split/\//,$_;

            $sip = unpack'N',pack'C4',split/\./,$sip;
            $eip = (2 ** (32 - $eip)) - 1;
            $sip &= ~ $eip;
            $eip |=   $sip;

            foreach($sip..$eip)
            {
                next if(($_ & 0xff) == 0) or (($_ & 0xff) == 0xff);

                my $target = join'.',unpack'C4',pack'N',$_;
                @{$a{$target}} = () if discover_one $target;
            }
        }
        elsif($_ =~ $iprangx)
        {
            my @sb = split/\./,$_;
            my @eb;

            for(my $i=0;$i<4;$i++) { ($sb[$i],$eb[$i]) = split/\-/,$sb[$i];  }
            for(my $i=0;$i<4;$i++) { $eb[$i] = $sb[$i] if ! defined $eb[$i]; }
            for(my $i=0;$i<4;$i++) {
                ($sb[$i],$eb[$i]) = ($eb[$i],$sb[$i]) if $sb[$i] > $eb[$i];
            }

            foreach my $i ($sb[0]..$eb[0]) { foreach my $j ($sb[1]..$eb[1]) {
            foreach my $k ($sb[2]..$eb[2]) { foreach my $l ($sb[3]..$eb[3]) {
                    next if ($l == 0) or ($l == 0xff);

                    my $target = join'.',($i,$j,$k,$l);
                    @{$a{$target}} = () if discover_one $target;
            }}}}
        }
        elsif($_ =~ $ipranjx)
        {
            my ($sip,$eip) = split/\-/,$_;
            $sip           = unpack'N',pack'C4',split/\./,$sip;
            my $len        = split/\./,$eip;

            if   ($len == 1) { $eip += $sip & 0xffffff00; }
            elsif($len == 2)
            {
                $eip  = unpack'n',pack'C2',split/\./,$eip;
                $eip += $sip & 0xffff0000;
            }
            elsif($len == 3)
            {
                $eip  = unpack'N',pack'xC3',split/\./,$eip;
                $eip += $sip & 0xff000000;
            }
            elsif($len == 4) { $eip = unpack'N',pack'C4',split/\./,$eip; }

            ($sip,$eip) = ($eip,$sip) if $sip > $eip;

            foreach($sip..$eip)
            {
                next if(($_ & 0xff) == 0) or (($_ & 0xff) == 0xff);

                my $target = join'.',unpack'C4',pack'N',$_;
                @{$a{$target}} = () if discover_one $target;
            }
        }
    }

    return %a;
}

sort_options;

my %result = discover $adr;
my $len    = keys %result;

print "No alive hosts found.\n" and exit(0) if     $len == 0;
print "Found 1 alive host :\n"              if     $len == 1;
print "Found $len alive hosts :\n"          unless $len == 1;

print "  - $_\n" foreach(keys %result);

sub scan
{
    my $bool  = $opt =~ $optstlhx;
    my $sleep = 1;

    if   ($opt =~ $optscanx)
    {
        foreach my $addr (keys %result) { while(<DATA>) {
            chomp and $prt = (split/\s+/,$_)[1];
            push@{$result{$addr}},$prt if scan_one $addr,$prt;
            sleep $sleep if $bool;
        }}
    }
    elsif($opt =~ $optfastx)
    {
        my $i = 0;

        foreach my $addr (keys %result) { while(<DATA>) {
            $i++;

            chomp and $prt = (split/\s+/,$_)[1];
            push@{$result{$addr}},$prt if scan_one $addr,$prt;
            sleep $sleep if $bool;

            last if $i == 100;
        }}
    }
    else
    {
        foreach my $addr (keys %result) { foreach(split/,/,$prt) {
            push@{$result{$addr}},$_ if $_ =~ $prtsmplx and scan_one $addr,$_;
            push@{$result{$addr}},scan_mul $addr,$_ if $_ =~ $prtrangx;
            sleep $sleep if $bool;
        }}
    }
}

scan if $opt !~ $optdscvx;

foreach my $addr (keys %result)
{
    $len = @{$result{$addr}};

    print "\nNo open ports found on $addr.\n" and next if     $len == 0;
    print "\nFound 1 open port on $addr :\n"           if     $len == 1;
    print "\nFound $len open ports on $addr :\n"       unless $len == 1;

    print "\n";

    print "Service"." "x 15;
    print "Port"." "x 3;
    print "Description\n";

    foreach $prt (@{$result{$addr}})
    {
        seek DATA,$pos,0;
        while (<DATA>) { print $_ if($prt == (split/\s+/,$_)[1]); }
    }
}

__DATA__
tcpmux                1      TCP Port Service Multiplexer
compressnet           2      Management Utility
compressnet           3      Compression Process
echo                  7
discard               9      sink null
systat                11     Active Users
daytime               13
netstat               15
qotd                  17     Quote of the Day
chargen               19     ttytst source Character Generator
ftp-data              20     File Transfer [Default Data]
ftp                   21     File Transfer [Control]
ssh                   22     Secure Shell Login
telnet                23
priv-mail             24     any private mail system
smtp                  25     Simple Mail Transfer
rsftp                 26     RSFTP
nsw-fe                27     NSW User System FE
msg-icp               29     MSG ICP
msg-auth              31     MSG Authentication
dsp                   33     Display Support Protocol
priv-print            35     any private printer server
time                  37     timserver
rap                   38     Route Access Protocol
nameserver            42     Host Name Server
whois                 43     nicname
mpm-flags             44     MPM FLAGS Protocol
mpm                   45     Message Processing Module [recv]
ni-ftp                47     NI FTP
auditd                48     Digital Audit Daemon
tacacs                49     Login Host Protocol
re-mail-ck            50     Remote Mail Checking Protocol
la-maint              51     IMP Logical Address Maintenance
xns-time              52     XNS Time Protocol
domain                53     Domain Name Server
xns-ch                54     XNS Clearinghouse
isi-gl                55     ISI Graphics Language
xns-auth              56     XNS Authentication
priv-term             57     any private terminal access
xns-mail              58     XNS Mail
priv-file             59     any private file service
tacacs-ds             65     TACACS-Database Service
sqlnet                66     Oracle SQL*NET
dhcps                 67     DHCP/Bootstrap Protocol Server
dhcpc                 68     DHCP/Bootstrap Protocol Client
tftp                  69     Trivial File Transfer
gopher                70
netrjs-1              71     Remote Job Service
netrjs-2              72     Remote Job Service
netrjs-3              73     Remote Job Service
netrjs-4              74     Remote Job Service
priv-dial             75     any private dial out service
deos                  76     Distributed External Object Store
priv-rje              77     any private RJE service, netrjs
finger                79
http                  80     World Wide Web HTTP
hosts2-ns             81     HOSTS2 Name Server
xfer                  82     XFER Utility
mit-ml-dev            83     MIT ML Device
ctf                   84     Common Trace Facility
mit-ml-dev            85     MIT ML Device
mfcobol               86     Micro Focus Cobol
priv-term-l           87     any private terminal link, ttylink
kerberos-sec          88     Kerberos (v5)
su-mit-tg             89     SU/MIT Telnet Gateway
dnsix                 90     DNSIX Securit Attribute Token Map
mit-dov               91     MIT Dover Spooler
npp                   92     Network Printing Protocol
dcp                   93     Device Control Protocol
objcall               94     Tivoli Object Dispatcher
supdup                95     BSD supdupd(8)
dixie                 96     DIXIE Protocol Specification
swift-rvf             97     Swift Remote Virtural File Protocol
linuxconf             98
metagram              99     Metagram Relay
newacct               100    [unauthorized use]
hostname              101    hostnames NIC Host Name Server
iso-tsap              102    tsap ISO-TSAP Class 0
gppitnp               103    Genesis Point-to-Point Trans Net
acr-nema              104    ACR-NEMA Digital Imag. & Comm. 300
pop3pw                106    Eudora compatible PW changer
snagas                108    SNA Gateway Access Server
pop2                  109    PostOffice V.2
pop3                  110    PostOffice V.3
rpcbind               111    portmapper, rpcbind
mcidas                112    McIDAS Data Transmission Protocol
ident                 113    ident, tap, Authentication Service
audionews             114    Audio News Multicast
sftp                  115    Simple File Transfer Protocol
ansanotify            116    ANSA REX Notify
uucp-path             117    UUCP Path Service
sqlserv               118    SQL Services
nntp                  119    Network News Transfer Protocol
cfdptkt               120
smakynet              122
ntp                   123    Network Time Protocol
ansatrader            124    ANSA REX Trader
locus-map             125    Locus PC-Interface Net Map Ser
locus-con             127    Locus PC-Interface Conn Server
gss-xlicen            128    GSS X License Verification
pwdgen                129    Password Generator Protocol
cisco-fna             130    cisco FNATIVE
cisco-sys             132    cisco SYSMAINT
statsrv               133    Statistics Service
msrpc                 135    Microsoft RPC services
profile               136    PROFILE Naming System
netbios-ns            137    NETBIOS Name Service
netbios-dgm           138    NETBIOS Datagram Service
netbios-ssn           139    NETBIOS Session Service
emfis-cntl            141    EMFIS Control Service
bl-idm                142    Britton-Lee IDM
imap                  143    Interim Mail Access Protocol v2
news                  144    NewS window system
iso-tp0               146
cronus                148    CRONUS-SUPPORT
aed-512               149    AED 512 Emulation Service
sql-net               150
hems                  151
knet-cmp              157    KNET/VM Command/Message Protocol
pcmail-srv            158    PCMail Server
snmp                  161
snmptrap              162    snmp-trap
cmip-man              163    CMIP/TCP Manager
rsvd                  168
xyplex-mux            173
mailq                 174
genrad-mux            176
xdmcp                 177    X Display Mgr. Control Proto
bgp                   179    Border Gateway Protocol
ris                   180    Intergraph
unify                 181
audit                 182    Unisys Audit SITP
ocserver              184
remote-kis            185
qft                   189    Queued File Transport
gacp                  190    Gateway Access Control Protocol
prospero              191    Prospero Directory Service
osu-nms               192    OSU Network Monitoring System
srmp                  193    Spider Remote Monitoring Protocol
irc                   194    Internet Relay Chat
dn6-smm-red           196    DNSIX Session Mgt Module Audit Redir
smux                  199    SNMP Unix Multiplexer
src                   200    IBM System Resource Controller
at-rtmp               201    AppleTalk Routing Maintenance
at-nbp                202    AppleTalk Name Binding
at-echo               204    AppleTalk Echo
at-5                  205    AppleTalk Unused
at-zis                206    AppleTalk Zone Information
tam                   209    Trivial Authenticated Mail Protocol
z39.50                210    wais, ANSI Z39.50
914c-g                211    Texas Instruments 914C/G Terminal
anet                  212    ATEXSSTR
ipx                   213
vmpwscs               214
atls                  216    Access Technology License Server
dbase                 217    dBASE Unix
uarps                 219    Unisys ARPs
imap3                 220    Interactive Mail Access Protocol v3
fln-spx               221    Berkeley rlogind with SPX auth
rsh-spx               222    Berkeley rshd with SPX auth
cdc                   223    Certificate Distribution Center
masqdialer            224
bhfhs                 248
fw1-secureremote      256    also "rap"
fw1-mc-fwmodule       257    FW1 management console for communication w/module
fw1-mc-gui            258    also yak winsock personal chat
esro-gen              259    efficient short remote operations
openport              260
nsiiops               261    iiop name service over tls/ssl
arcisdms              262
bgmp                  264
maybe-fw1             265
td-service            267    Tobit David Service Layer
td-replica            268    Tobit David Replica
http-mgmt             280
corerjd               284
novastorbakcup        308    novastor backup
asip-webadmin         311    appleshare ip webadmin
dpsi                  315
decauth               316
rtsps                 322    RTSPS
texar                 333    Texar Security Port
zserv                 346    Zebra server
matip-type-a          350    MATIP Type A
matip-type-b          351    MATIP Type B or bhoetty also safetp
dtag-ste-sb           352    DTAG, or bhoedap4
ndsauth               353
datex-asn             355
shrinkwrap            358
scoi2odialog          360
semantix              361
srssend               362    SRS Send
aurora-cmgr           364
odmr                  366
rpc2portmap           369
codaauth2             370
legent-1              373    Legent Corporation (Computer Associates Intl.)
is99s                 380    TIA/EIA/IS-99 modem server
hp-alarm-mgr          383    hp performance data alarm manager
unidata-ldm           388    Unidata LDM Version 4
ldap                  389    Lightweight Directory Access Protocol
synotics-relay        391    SynOptics SNMP Relay Port
synotics-broker       392    SynOptics Port Broker Port
mptn                  397    Multi Protocol Trans. Net.
iso-tsap-c2           399    ISO-TSAP Class 2
work-sol              400    Workstation Solutions
ups                   401    Uninterruptible Power Supply
genie                 402    Genie Protocol
decap                 403
nced                  404
imsp                  406    Interactive Mail Support Protocol
timbuktu              407
prm-sm                408    Prospero Resource Manager Sys. Man.
decladebug            410    DECLadebug Remote Debug Protocol
rmt                   411    Remote MT Protocol
synoptics-trap        412    Trap Convention Port
smsp                  413
infoseek              414
bnet                  415
silverplatter         416
onmux                 417    Meeting maker
hyper-g               418
ariel1                419
smpte                 420
ariel3                422
opc-job-start         423    IBM Operations Planning and Control Start
icad-el               425
svrloc                427    Server Location
ocs_cmu               428
iasd                  432
mobileip-agent        434
mobilip-mn            435
comscm                437
dsfgw                 438
dasp                  439
sgcp                  440
decvms-sysmgt         441
cvc_hostd             442
https                 443    secure http (SSL)
snpp                  444    Simple Network Paging Protocol
microsoft-ds          445    SMB directly over IP
ddm-rdb               446
ddm-dfm               447
ddm-ssl               448    ddm-byte
as-servermap          449    AS Server Mapper
tserver               450
sfs-smp-net           451    Cray Network Semaphore server
sfs-config            452    Cray SFS config server
creativeserver        453
contentserver         454
macon                 456
scohelp               457
appleqtc              458    apple quick time
skronk                460
datasurfsrvsec        462
kpasswd5              464    Kerberos (v5)
smtps                 465    smtp protocol over TLS/SSL (was ssmtp)
digital-vrc           466
scx-proxy             470
ljk-login             472
hybrid-pop            473
tcpnethaspsrv         475
iafserver             479
loadsrv               480
dvs                   481
powerburst            485    Air Soft Power Burst
sstats                486
saft                  487    saft Simple Asynchronous File Transfer
go-login              491
ticf-1                492    Transport Independent Convergence for FNA
ticf-2                493    Transport Independent Convergence for FNA
pim-rp-disc           496
retrospect            497
isakmp                500
stmf                  501
asa-appl-proto        502
mailbox-lm            505
crs                   507
snare                 509
fcp                   510    FirstClass Protocol
passgo                511
exec                  512    BSD rexecd(8)
login                 513    BSD rlogind(8)
shell                 514    BSD rshd(8)
printer               515    spooler (lpd)
videotex              516
ntalk                 518    (talkd)
ulp                   522
ibm-db2               523
ncp                   524
timed                 525    timeserver
tempo                 526    newdate
custix                528    Customer IXChange
courier               530    rpc
netwall               533    for emergency broadcasts
iiop                  535
opalis-rdv            536
gdomap                538
uucp                  540    uucpd
uucp-rlogin           541
commerce              542
klogin                543    Kerberos (v4/v5)
kshell                544    krcmd Kerberos (v4/v5)
ekshell               545    Kerberos encrypted remote shell -kfall
afp                   548    AFP over TCP
deviceshare           552
pirp                  553
rtsp                  554    Real Time Stream Control Protocol
dsf                   555
remotefs              556    rfs, rfs_server, Brunhoff remote filesystem
openvms-sysipc        557
rmonitor              560    rmonitord
monitor               561
snews                 563
9pfs                  564    plan 9 file service
ms-shuttle            568    Microsoft shuttle
ms-rome               569    Microsoft rome
meter                 570    demon
umeter                571    udemon
sonar                 572
vnas                  577
ipdd                  578
scc-security          582
philips-vc            583    Philips Video-Conferencing
submission            587
http-alt              591    FileMaker, Inc. - HTTP Alternate
http-rpc-epmap        593    HTTP RPC Ep Map
smsd                  596
sco-websrvrmg3        598    SCO Web Server Manager 3
acp                   599    Aeolon Core Protocol
ipcserver             600    Sun IPC server
syslog-conn           601    Reliable Syslog Service
xmlrpc-beep           602    XML-RPC over BEEP
mnotes                603    CommonTime Mnotes PDA Synchronization
tunnel                604    TUNNEL
soap-beep             605    SOAP over BEEP
urm                   606    Cray Unified Resource Manager
nqs                   607
sift-uft              608    Sender-Initiated/Unsolicited File Transfer
npmp-trap             609
npmp-local            610
npmp-gui              611
hmmp-ind              612    HMMP Indication
hmmp-op               613    HMMP Operation
sshell                614    SSLshell
sco-inetmgr           615    Internet Configuration Manager
sco-sysmgr            616    SCO System Administration Server
sco-dtmgr             617    SCO Desktop Administration Server or Arkeia
dei-icda              618    DEI-ICDA
compaq-evm            619    Compaq EVM
sco-websrvrmgr        620    SCO WebServer Manager
escp-ip               621    ESCP
collaborator          622    Collaborator
oob-ws-http           623    DMTF out-of-band web services management protocol
cryptoadmin           624    Crypto Admin
apple-xsrvr-admin     625    Apple Mac Xserver admin
apple-imap-admin      626    Apple IMAP mail admin
passgo-tivoli         627    PassGo Tivoli
qmqp                  628    Qmail Quick Mail Queueing
3com-amp3             629    3Com AMP3
rda                   630    RDA
ipp                   631    Internet Printing Protocol
bmpp                  632
servstat              633    Service Status update (Sterling Software)
ginad                 634
rlzdbase              635    RLZ DBase
ldapssl               636    LDAP over SSL
lanserver             637
mcns-sec              638
msdp                  639    MSDP
entrust-sps           640
repcmd                641
esro-emsdp            642    ESRO-EMSDP V1.3
sanity                643    SANity
dwr                   644
pssc                  645    PSSC
ldp                   646    Label Distribution
dhcp-failover         647    DHCP Failover
rrp                   648    Registry Registrar Protocol (RRP)
cadview-3d            649    Cadview-3d - streaming 3d models over internet
ieee-mms              651    IEEE MMS
hello-port            652    HELLO_PORT
repscmd               653    RepCmd
aodv                  654    AODV
tinc                  655    TINC
spmp                  656    SPMP
rmc                   657    RMC
tenfold               658    TenFold
mac-srvr-admin        660    MacOS Server Admin
hap                   661    HAP
pftp                  662    PFTP
purenoise             663    PureNoise
secure-aux-bus        664
sun-dr                665    Sun DR
doom                  666    Id Software Doom
disclose              667    campaign contribution disclosures -SDR Technology
mecomm                668    MeComm
meregister            669    MeRegister
vacdsm-sws            670    VACDSM-SWS
vpps-qua              672    VPPS-QUA
cimplex               673    CIMPLEX
acap                  674    ACAP server of Communigate
dctp                  675    DCTP
vpps-via              676    VPPS Via
vpp                   677    Virtual Presence Protocol
ggf-ncp               678    GNU Generation Foundation NCP
entrust-aaas          680
entrust-aams          681
xfr                   682    XFR
corba-iiop            683
corba-iiop-ssl        684    CORBA IIOP SSL
mdc-portmapper        685    MDC Port Mapper
hcp-wismar            686    Hardware Control Protocol Wismar
asipregistry          687
realm-rusd            688    ApplianceWare managment protocol
nmap                  689    NMAP
vatp                  690    Velazquez Application Transfer Protocol
resvc                 691    Microsoft Exchange 2000 Server Routing Service
hyperwave-isp         692    Hyperwave-ISP
ha-cluster            694
ieee-mms-ssl          695    IEEE-MMS-SSL
rushd                 696    RUSHD
uuidgen               697    UUIDGEN
olsr                  698    OLSR
accessnetwork         699    Access Network
epp                   700    Extensible Provisioning Protocol
lmp                   701    Link Management Protocol (LMP)
iris-beep             702    IRIS over BEEP
elcsd                 704    errlog copy/server daemon
agentx                705    AgentX
silc                  706    Secure Internet Live Conferencing
borland-dsj           707    Borland DSJ
entrustmanager        709    EntrustManager - NorTel DES auth network
entrust-ash           710    Entrust Administration Service Handler
cisco-tdp             711    Cisco TDP
tbrpf                 712    TBRPF
iris-xpc              713    IRIS over XPC
iris-xpcs             714    IRIS over XPCS
iris-lwz              715    IRIS-LWZ
omfs                  723    OpenMosix File System
netviewdm1            729    IBM NetView DM/6000 Server/Client
netviewdm2            730    IBM NetView DM/6000 send/tcp
netviewdm3            731    IBM NetView DM/6000 receive/tcp
netcp                 740    NETscout Control Protocol
netgw                 741
netrcs                742    Network based Rev. Cont. Sys.
flexlm                744    Flexible License Manager
fujitsu-dev           747    Fujitsu Device Control
ris-cm                748    Russell Info Sci Calendar Manager
kerberos-adm          749    Kerberos 5 admin/changepw
kerberos              750    kdc Kerberos (v4)
kerberos_master       751    Kerberos `kadmin' (v4)
qrh                   752
rrh                   753
krb_prop              754    kerberos/v5 server propagation
nlogin                758
con                   759
krbupdate             760    kreg Kerberos (v4) registration
kpasswd               761    kpwd Kerberos (v4) "passwd"
quotad                762
cycleserv             763
omserv                764
webster               765
phonebook             767    phone
vid                   769
cadlock               770
rtip                  771
submit                773
rpasswd               774
entomb                775
wpages                776
multiling-http        777    Multiling HTTP
wpgs                  780
hp-collector          781    hp performance data collector
hp-managed-node       782    hp performance data managed node
spamassassin          783    Apache SpamAssassin spamd
concert               786
qsc                   787
controlit             799    Remotely possible
mdbs_daemon           800
device                801
ccproxy-http          808    CCProxy HTTP/Gopher/FTP (over HTTP) proxy
fcp-udp               810    FCP
itm-mcell-s           828
pkix-3-ca-ra          829    PKIX-3 CA/RA
netconf-ssh           830    NETCONF over SSH
netconf-beep          831    NETCONF over BEEP
netconfsoaphttp       832    NETCONF for SOAP over HTTPS
netconfsoapbeep       833    NETCONF for SOAP over BEEP
dhcp-failover2        847    dhcp-failover 2
gdoi                  848    GDOI
iscsi                 860    iSCSI
owamp-control         861    OWAMP-Control
twamp-control         862    Two-way Active Measurement Protocol Control
supfilesrv            871    SUP server
rsync                 873    Rsync server
iclcnet-locate        886    ICL coNETion locate server
iclcnet_svinfo        887    ICL coNETion server info
accessbuilder         888    or Audio CD Database
sun-manageconsole     898    Solaris Management Console Java listener
omginitialrefs        900    OMG Initial Refs
samba-swat            901    Samba SWAT tool.  Also used by ISS RealSecure.
iss-realsecure        902    ISS RealSecure Sensor
iss-console-mgr       903    ISS Console Manager
kink                  910    Kerberized Internet Negotiation of Keys (KINK)
xact-backup           911
apex-mesh             912    APEX relay-relay service
apex-edge             913    APEX endpoint-relay service
oftep-rpc             950    Often RPC.statd (on Redhat Linux)
rndc                  953    RNDC is used by BIND 9 (& probably other NS)
securenetpro-sensor   975
ftps-data             989    ftp protocol, data, over TLS/SSL
ftps                  990    ftp protocol, control, over TLS/SSL
nas                   991    Netnews Administration System
telnets               992    telnet protocol over TLS/SSL
imaps                 993    imap4 protocol over TLS/SSL
ircs                  994    irc protocol over TLS/SSL
pop3s                 995    POP3 protocol over TLS/SSL
xtreelic              996    XTREE License Server
maitrd                997
busboy                998
garcon                999
cadlock               1000
windows-icfw          1002   Windows Internet Connection Firewall
ufsd                  1008   UFS-aware server
surf                  1010
exp1                  1021   RFC3692-style Experiment 1
exp2                  1022   RFC3692-style Experiment 2
netvenuechat          1023   Nortel NetVenue Notification, Chat, Intercom
kdm                   1024   K Display Manager (KDE version of xdm)
NFS-or-IIS            1025   IIS, NFS, or listener RFS remote_file_sharing
LSA-or-nterm          1026   nterm remote_login network_terminal
IIS                   1027
ms-lsa                1029
iad1                  1030   BBN IAD
iad2                  1031   BBN IAD
iad3                  1032   BBN IAD
netinfo               1033   Netinfo is apparently on many OS X boxes.
zincite-a             1034   Zincite.A backdoor
multidropper          1035   A Multidropper Adware, or PhoneFree
nsstp                 1036   Nebula Secure Segment Transfer Protocol
ams                   1037   AMS
mtqp                  1038   Message Tracking Query Protocol
sbl                   1039   Streamlined Blackhole
netsaint              1040   Netsaint status daemon
danf-ak2              1041   AK2 Product
afrog                 1042   Subnet Roaming
boinc                 1043   BOINC Client Control or Microsoft IIS
dcutility             1044   Dev Consortium Utility
fpitp                 1045   Fingerprint Image Transfer Protocol
wfremotertm           1046   WebFilter Remote Monitor
neod1                 1047   Sun's NEO Object Request Broker
neod2                 1048   Sun's NEO Object Request Broker
td-postman            1049   Tobit David Postman VPMN
java-or-OTGfileshare  1050   J2EE nameserver
optima-vnet           1051
ddt                   1052   Dynamic DNS tools
remote-as             1053   Remote Assistant (RA)
brvread               1054   BRVREAD
ansyslmd              1055
vfo                   1056   VFO
startron              1057   STARTRON
nim                   1058
nimreg                1059
polestar              1060
kiosk                 1061   KIOSK
veracity              1062
kyoceranetdev         1063   KyoceraNetDev
jstel                 1064   JSTEL
syscomlan             1065   SYSCOMLAN
fpo-fns               1066
instl_boots           1067   Installation Bootstrap Proto. Serv.
instl_bootc           1068   Installation Bootstrap Proto. Cli.
cognex-insight        1069
gmrupdateserv         1070   GMRUpdateSERV
bsquare-voip          1071   BSQUARE-VOIP
cardax                1072   CARDAX
bridgecontrol         1073   Bridge Control
warmspotMgmt          1074   Warmspot Management Protocol
rdrmshc               1075   RDRMSHC
sns_credit            1076   SNS for Canadian credit card authorizations
imgames               1077   IMGames
avocent-proxy         1078   Avocent Proxy Protocol
asprovatalk           1079   ASPROVATalk
socks                 1080
pvuniwien             1081   PVUNIWIEN
amt-esd-prot          1082   AMT-ESD-PROT
ansoft-lm-1           1083   Anasoft License Manager
ansoft-lm-2           1084   Anasoft License Manager
webobjects            1085   Web Objects
cplscrambler-lg       1086   CPL Scrambler Logging
cplscrambler-in       1087   CPL Scrambler Internal
cplscrambler-al       1088   CPL Scrambler Alarm Log
ff-annunc             1089   FF Annunciation
ff-fms                1090   FF Fieldbus Message Specification
ff-sm                 1091   FF System Management
obrpd                 1092   Open Business Reporting Protocol
proofd                1093   PROOFD
rootd                 1094   ROOTD
nicelink              1095   NICELink
cnrprotocol           1096   Common Name Resolution Protocol
sunclustermgr         1097   Sun Cluster Manager
rmiactivation         1098   RMI Activation
rmiregistry           1099   RMI Registry
mctp                  1100   MCTP
pt2-discover          1101   PT2-DISCOVER
adobeserver-1         1102   ADOBE SERVER 1
xaudio                1103   X Audio Server
xrl                   1104   XRL
ftranhc               1105   FTRANHC
isoipsigport-1        1106   ISOIPSIGPORT-1
isoipsigport-2        1107   ISOIPSIGPORT-2
ratio-adp             1108
kpop                  1109   Pop with Kerberos
nfsd-status           1110   Cluster status info
lmsocialserver        1111   LM Social Server
msql                  1112   mini-sql server
ltp-deepspace         1113   Licklider Transmission Protocol
mini-sql              1114   Mini SQL
ardus-cntl            1116   ARDUS Control
ardus-mtrns           1117   ARDUS Multicast Transfer
sacred                1118   SACRED
bnetgame              1119   Battle.net Chat/Game Protocol
rmpp                  1121   Datalode RMPP
availant-mgr          1122
murray                1123   Murray
hpvmmcontrol          1124   HP VMM Control
hpvmmagent            1125   HP VMM Agent
hpvmmdata             1126   HP VMM Agent
supfiledbg            1127   SUP debugging
saphostctrl           1128   SAPHostControl over SOAP/HTTP
casp                  1130   CAC App Service Protocol
caspssl               1131   CAC App Service Protocol Encripted
kvm-via-ip            1132   KVM-via-IP Management Service
aplx                  1134   MicroAPL APLX
omnivision            1135   OmniVision Communication Service
hhb-gateway           1136   HHB Gateway Control
trim                  1137   TRIM Workgroup Service
encrypted_admin       1138   encrypted admin requests
cce3x                 1139   ClearCommerce Engine 3.x
mxomss                1141   User Message Service
imyx                  1143   Infomatryx Exchange
fuscript              1144   Fusion Script
x9-icue               1145   X9 iCue Show Control
capioverlan           1147   CAPIoverLAN
elfiq-repl            1148   Elfiq Replication Service
bvtsonar              1149   BVT Sonar Service
blaze                 1150   Blaze File Server
unizensus             1151   Unizensus Login Server
winpoplanmess         1152   Winpopup LAN Messenger
c1222-acse            1153   ANSI C12.22 Port
resacommunity         1154   Community Service
iascontrol-oms        1156   iasControl OMS
iascontrol            1157   Oracle iASControl
lsnr                  1158   Oracle DB listener
oracle-oms            1159   Oracle OMS
health-trap           1162   Health Trap
sddp                  1163   SmartDialer Data Protocol
qsm-proxy             1164   QSM Proxy Service
qsm-gui               1165   QSM GUI Service
qsm-remote            1166   QSM RemoteExec
cisco-ipsla           1167   Cisco IP SLAs Control Protocol
vchat                 1168   VChat Conference Service
tripwire              1169   TRIPWIRE
d-cinema-rrp          1173   D-Cinema Request-Response
fnet-remote-ui        1174   FlashNet Remote Admin
dossier               1175   Dossier Server
indigo-server         1176   Indigo Home Server
skkserv               1178   SKK (kanji input)
b2n                   1179   Backup To Neighbor
mc-client             1180   Millicent Client Proxy
accelenet             1182   AcceleNet Control
llsurfup-http         1183   LL Surfup HTTP
llsurfup-https        1184   LL Surfup HTTPS
catchpole             1185   Catchpole port
mysql-cluster         1186   MySQL Cluster Manager
alias                 1187   Alias Service
hp-webadmin           1188   HP Web Admin
commlinx-avl          1190   CommLinx GPS / AVL System
gpfs                  1191   General Parallel File System
caids-sensor          1192   caids sensors channel
openvpn               1194   OpenVPN
rsf-1                 1195   RSF-1 clustering
netmagic              1196   Network Magic
cajo-discovery        1198   cajo reference discovery
dmidi                 1199   DMIDI
scol                  1200   SCOL
nucleus-sand          1201   Nucleus Sand Database Server
ssslog-mgr            1204   Log Request Listener
metasage              1207   MetaSage
seagull-ais           1208   SEAGULL AIS
ipcd3                 1209   IPCD3
eoss                  1210   EOSS
groove-dpp            1211   Groove DPP
lupa                  1212
mpc-lifenet           1213   MPC LIFENET
fasttrack             1214   Kazaa File Sharing
scanstat-1            1215   scanSTAT 1.0
etebac5               1216   ETEBAC 5
hpss-ndapi            1217   HPSS NonDCE Gateway
aeroflight-ads        1218   AeroFlight ADs
quicktime             1220   AppleDarwin and QuickTimeStreaming Administration
sweetware-apps        1221   SweetWARE Apps
nerv                  1222   SNI R&D network
tgp                   1223   TrulyGlobal Protocol
florence              1228   FLORENCE
zented                1229   ZENworks Tiered Electronic Distribution
univ-appserver        1233   Universal App Server
hotline               1234
bvcontrol             1236
nmsd                  1239   NMSD
instantia             1240   Instantia
nessus                1241   Nessus or remote message server
serialgateway         1243   SerialGateway
isbconference1        1244
visionpyramid         1247   VisionPyramid
hermes                1248
mesavistaco           1249   Mesa Vista Co
swldy-sias            1250
servergraph           1251
opennl-voice          1259   Open Network Library Voice
mpshrsv               1261
qnts-orb              1262   QNTS-ORB
prat                  1264   PRAT
propel-msgsys         1268   PROPEL-MSGSYS
ssserver              1270   Sun StorEdge Configuration Service
excw                  1271   eXcW
cspmlockmgr           1272   CSPMLockMgr
ivmanager             1276
miva-mqs              1277   mqs
dellwebadmin-2        1279   Dell Web Admin 2
emperion              1282   Emperion
routematch            1287   RouteMatch Com
winjaserver           1290   WinJaServer
seagulllms            1291   SEAGULLLMS
dproxy                1296
sdproxy               1297
hp-sci                1299
h323hostcallsc        1300   H323 Host Call Secure
ci3-software-1        1301   CI3-Software-1
ci3-software-2        1302   CI3-Software-2
sftsrv                1303
pe-mike               1305
re-conn-proto         1306   RE-Conn-Proto
pacmand               1307   Pacmand
odsi                  1308   Optical Domain Service Interconnect (ODSI)
jtag-server           1309   JTAG server
husky                 1310   Husky
rxmon                 1311
pdps                  1314   Photoscript Distributed Printing System
els                   1315   E.L.S., Event Listener Service
exbit-escp            1316   Exbit-ESCP
vrts-ipcserver        1317
krb5gatekeeper        1318
amx-icsp              1319   AMX-ICSP
pip                   1321   PIP
novation              1322   Novation
delta-mcp             1324
ultrex                1327   Ultrex
ewall                 1328   EWALL
streetperfect         1330   StreetPerfect
intersan              1331
writesrv              1334
ischat                1336   Instant Service Chat
waste                 1337   Nullsoft WASTE encrypted P2P app
kjtsiteserver         1339
naap                  1340   NAAP
alta-ana-lm           1346   Alta Analytics License Manager
bbn-mmc               1347   multi media conferencing
bbn-mmx               1348   multi media conferencing
sbook                 1349   Registration Network Protocol
editbench             1350   Registration Network Protocol
equationbuilder       1351   Digital Tool Works (MIT)
lotusnotes            1352   Lotus Note
relief                1353   Relief Consulting
rightbrain            1354   RightBrain Software
intuitive-edge        1355   Intuitive Edge
cuillamartin          1356   CuillaMartin Company
pegboard              1357   Electronic PegBoard
connlcli              1358
ftsrv                 1359
mimer                 1360
linx                  1361
timeflies             1362
ndm-requester         1363   Network DataMover Requester
ndm-server            1364   Network DataMover Server
adapt-sna             1365   Network Software Associates
netware-csp           1366   Novell NetWare Comm Service Platform
dcs                   1367
screencast            1368
gv-us                 1369   GlobalView to Unix Shell
us-gv                 1370   Unix Shell to GlobalView
fc-cli                1371   Fujitsu Config Protocol
fc-ser                1372   Fujitsu Config Protocol
chromagrafx           1373
molly                 1374   EPI Software Systems
ibm-pps               1376   IBM Person to Person Software
dbreporter            1379   Integrity Solutions
apple-licman          1381   Apple Network License Manager
gwha                  1383   GW Hannaway Network License Manager
os-licman             1384   Objective Solutions License Manager
atex_elmd             1385   Atex Publishing License Manager
checksum              1386   CheckSum License Manager
cadsi-lm              1387   Computer Aided Design Software Inc LM
objective-dbc         1388   Objective Solutions DataBase Cache
iclpv-dm              1389   Document Manager
iclpv-sc              1390   Storage Controller
iclpv-sas             1391   Storage Access Server
iclpv-nls             1393   Network Log Server
iclpv-nlc             1394   Network Log Client
iclpv-wsm             1395   PC Workstation Manager software
dvl-activemail        1396   DVL Active Mail
audio-activmail       1397   Audio Active Mail
video-activmail       1398   Video Active Mail
cadkey-licman         1399   Cadkey License Manager
cadkey-tablet         1400   Cadkey Tablet Daemon
goldleaf-licman       1401   Goldleaf License Manager
prm-sm-np             1402   Prospero Resource Manager
prm-nm-np             1403   Prospero Resource Manager
igi-lm                1404   Infinite Graphics License Manager
ibm-res               1405   IBM Remote Execution Starter
dbsa-lm               1407   DBSA License Manager
sophia-lm             1408   Sophia License Manager
here-lm               1409   Here License Manager
hiq                   1410   HiQ License Manager
af                    1411   AudioFile
innosys               1412
innosys-acl           1413
ibm-mqseries          1414   IBM MQSeries
novell-lu6.2          1416   Novell LU6.2
timbuktu-srv1         1417   Timbuktu Service 1 Port
timbuktu-srv2         1418   Timbuktu Service 2 Port
timbuktu-srv3         1419   Timbuktu Service 3 Port
timbuktu-srv4         1420   Timbuktu Service 4 Port
autodesk-lm           1422   Autodesk License Manager
essbase               1423   Essbase Arbor Software
hybrid                1424   Hybrid Encryption Protocol
sas-1                 1426   Satellite-data Acquisition System 1
mloadd                1427   mloadd monitoring tool
nms                   1429   Hypercom NMS
tpdu                  1430   Hypercom TPDU
blueberry-lm          1432   Blueberry Software License Manager
ms-sql-s              1433   Microsoft-SQL-Server
ms-sql-m              1434   Microsoft-SQL-Monitor
ibm-cics              1435
sas-2                 1436   Satellite-data Acquisition System 2
tabula                1437
eicon-server          1438   Eicon Security Agent/Server
eicon-x25             1439   Eicon X25/SNA Gateway
eicon-slp             1440   Eicon Service Location Protocol
cadis-1               1441   Cadis License Management
cadis-2               1442   Cadis License Management
ies-lm                1443   Integrated Engineering Software
marcam-lm             1444   Marcam License Management
proxima-lm            1445   Proxima License Manager
ora-lm                1446   Optical Research Associates License Manager
oc-lm                 1448   OpenConnect License Manager
peport                1449
infoman               1451   IBM Information Management
genie-lm              1453   Genie License Manager
interhdl_elmd         1454   interHDL License Manager
esl-lm                1455   ESL License Manager
dca                   1456
valisys-lm            1457   Valisys License Manager
nrcabq-lm             1458   Nichols Research Corp.
proshare1             1459   Proshare Notebook Application
ibm_wrless_lan        1461   IBM Wireless LAN
world-lm              1462   World License Manager
msl_lmd               1464   MSL License Manager
pipes                 1465   Pipes Platform
oceansoft-lm          1466   Ocean Software License Manager
csdmbase              1467
aal-lm                1469   Active Analysis Limited License Manager
uaiact                1470   Universal Analytics
csdm                  1472
openmath              1473
telefinder            1474
taligent-lm           1475   Taligent License Manager
clvm-cfg              1476
dberegister           1479
pacerforum            1480
miteksys-lm           1482   Miteksys License Manager
afs                   1483   AFS License Manager
confluent             1484   Confluent License Manager
nms_topo_serv         1486
docstor               1488
anynetgateway         1491
stone-design-1        1492
netmap_lm             1493
citrix-ica            1494
cvc                   1495
liberty-lm            1496
rfx-lm                1497
watcom-sql            1498
fhc                   1499   Federico Heinz Consultora
vlsi-lm               1500   VLSI License Manager
sas-3                 1501   Satellite-data Acquisition System 3
shivadiscovery        1502   Shiva
imtc-mcs              1503   Databeam
funkproxy             1505   Funk Software, Inc.
symplex               1507
diagmond              1508
robcad-lm             1509   Robcad, Ltd. License Manager
mvx-lm                1510   Midland Valley Exploration Ltd. Lic. Man.
3l-l1                 1511
fujitsu-dtc           1513   Fujitsu Systems Business of America, Inc
ifor-protocol         1515
vpad                  1516   Virtual Places Audio data
vpac                  1517   Virtual Places Audio control
vpvd                  1518   Virtual Places Video data
vpvc                  1519   Virtual Places Video control
oracle                1521   Oracle Database
rna-lm                1522   Ricardo North America License Manager
cichild-lm            1523
ingreslock            1524   ingres
orasrv                1525   oracle or Prospero Directory Service non-priv
pdap-np               1526   Prospero Data Access Prot non-priv
tlisrv                1527   oracle
mciautoreg            1528
support               1529   cygnus bug tracker
rap-listen            1531
miroconnect           1532
virtual-places        1533   Virtual Places Software
ampr-info             1535
sdsc-lm               1537
3ds-lm                1538
intellistor-lm        1539   Intellistor License Manager
rds                   1540
rds2                  1541
gridgen-elmd          1542
simba-cs              1543
aspeclmd              1544
vistium-share         1545
laplink               1547
axon-lm               1548   Axon License Manager
shivahose             1549   Shiva Hose
3m-image-lm           1550   Image Storage license manager 3M Company
hecmtl-db             1551
pciarray              1552
veritas_pbx           1556   VERITAS Private Branch Exchange
xingmpeg              1558
web2host              1559
asci-val              1560   ASCI-RemoteSHADOW
winddlb               1565   WinDD
corelvideo            1566   CORELVIDEO
ets                   1569
tn-tl-r1              1580
simbaexpress          1583
tn-tl-fd2             1584
commonspace           1592
sixtrak               1594
picknfs               1598
issd                  1600
slp                   1605   Salutation Manager (Salutation Protocol)
stt                   1607
netbill-auth          1615   NetBill Authorization Server
faxportwinport        1620
ontime                1622
pammratc              1632   PAMMRATC
edb-server1           1635   EDB Server 1
ismc                  1638   ISP shared management control
invision              1641   InVision
sightline             1645   SightLine
nkd                   1650
shiva_confsrvr        1651
xnmp                  1652
sixnetudr             1658
netview-aix-1         1661
netview-aix-2         1662
netview-aix-3         1663
netview-aix-4         1664
netview-aix-6         1666
netview-aix-7         1667
netview-aix-8         1668
netview-aix-10        1670
netview-aix-11        1671
netview-aix-12        1672
groupwise             1677
CarbonCopy            1680
ncpm-hip              1683
nsjtp-ctrl            1687
nsjtp-data            1688
empire-empuma         1691
rrimwm                1694
rsvp-encap-2          1699   RSVP-ENCAPSULATION-2
mps-raft              1700
l2f                   1701
hb-engine             1703
vdmplay               1707
gat-lmd               1708
centra                1709
pptconference         1711
registrar             1712   resource monitoring service
conferencetalk        1713   ConferenceTalk
houdini-lm            1715
fj-hdnet              1717
h323gatedisc          1718
h323gatestat          1719
H.323/Q.931           1720   Interactive media
caicci                1721
hks-lm                1722   HKS License Manager
pptp                  1723   Point-to-point tunnelling protocol
roketz                1730
privatechat           1735   PrivateChat
street-stream         1736
remote-winsock        1745
sslp                  1750   Simple Socket Library's PortMaster
lofr-lm               1752   Leap of Faith Research License Manager
wms                   1755   Windows media service
landesk-rc            1761   LANDesk Remote Control
landesk-rc            1762   LANDesk Remote Control
landesk-rc            1763   LANDesk Remote Control
hp-hcip               1782
ea1                   1791   EA1
ibm-dt-2              1792
netrisk               1799   NETRISK
ansys-lm              1800   ANSYS-License manager
msmq                  1801   Microsoft Message Queuing
enl-name              1805   ENL-Name
musiconline           1806   Musiconline
fhsp                  1807   Fujitsu Hot Standby Protocol
oracle-vp2            1808   Oracle-VP2
scientia-sdb          1811   Scientia-SDB
radius                1812   RADIUS
unisys-lm             1823   Unisys Natural Language License Manager
direcpc-video         1825   DirecPC Video
pcm                   1827   PCM Agent (AutoSecure Policy Compliance Manager
ardusmul              1835   ARDUS Multicast
netopia-vo1           1839
netopia-vo2           1840
privateark            1858   PrivateArk
lecroy-vicp           1861   LeCroy VICP
mysql-cm-agent        1862   MySQL Cluster Manager Agent
msnp                  1863   MSN Messenger
paradym-31            1864
canocentral0          1871   Cano Central 0
westell-stats         1875   westell stats
upnp                  1900   Universal PnP
fjicl-tep-a           1901   Fujitsu ICL Terminal Emulator Program A
mtp                   1911   Starlight Networks Multimedia Transport Protocol
rhp-iibp              1912
elm-momentum          1914   Elm-Momentum
can-nds               1918   IBM Tivole Directory Service - NDS
xiip                  1924   XIIP
videte-cipc           1927   Videte CIPC Port
rtmp                  1935   Macromedia FlasComm Server
sentinelsrm           1947   SentinelSRM
abr-api               1954   ABR-API (diskbridge)
dxadmind              1958   CA Administration Daemon
netop-school          1971   NetOp School
intersys-cache        1972   Cache
dlsrap                1973   Data Link Switching Remote Access Protocol
drp                   1974   DRP
tcoflashagent         1975   TCO Flash Agent
tcoregagent           1976   TCO Reg Agent
p2pq                  1981   p2pQ
bigbrother            1984   Big Brother monitoring server
licensedaemon         1986   cisco license management
tr-rsrb-p1            1987   cisco RSRB Priority 1 port
tr-rsrb-p2            1988   cisco RSRB Priority 2 port
tr-rsrb-p3            1989   cisco RSRB Priority 3 port
stun-p1               1990   cisco STUN Priority 1 port
stun-p2               1991   cisco STUN Priority 2 port
stun-p3               1992   cisco STUN Priority 3 port
snmp-tcp-port         1993   cisco SNMP TCP port
stun-port             1994   cisco serial tunnel port
perf-port             1995   cisco perf port
tr-rsrb-port          1996   cisco Remote SRB port
gdp-port              1997   cisco Gateway Discovery Protocol
x25-svc-port          1998   cisco X.25 service (XOT)
tcp-id-port           1999   cisco identification port
cisco-sccp            2000   cisco SCCP (Skinny Client Control Protocol)
dc                    2001   or nfr20 web queries
globe                 2002
finger                2003   GNU finger (cfingerd)
mailbox               2004
deslogin              2005   encrypted symmetric telnet/login
invokator             2006
dectalk               2007
conf                  2008
news                  2009
search                2010   Or nfr411
raid-cc               2011   raid
ttyinfo               2012
raid-am               2013
troff                 2014
cypress               2015
bootserver            2016
terminaldb            2018
whosockami            2019
xinupageserver        2020
servexec              2021
down                  2022
xinuexpansion3        2023
xinuexpansion4        2024
ellpack               2025
scrabble              2026
shadowserver          2027
submitserver          2028
device2               2030
mobrien-chat          2031
glogger               2033
scoremgr              2034
imsldoc               2035
objectmanager         2038
lam                   2040
interbase             2041
isis                  2042
isis-bcast            2043
rimsl                 2044
cdfunc                2045
sdfunc                2046
dls                   2047
dls-monitor           2048
nfs                   2049   networked file system
knetd                 2053
icg-swp               2062   ICG SWP Port
dnet-keyproxy         2064   A client for solving the RSA challenge
dlsrpn                2065   Data Link Switch Read Port Number
dlswpn                2067   Data Link Switch Write Port Number
advocentkvm           2068   Advocent KVM Server
event-port            2069   HTTP Event Port
ah-esp-encap          2070   AH and ESP Encapsulated in UDP packet
autodesk-nlm          2080   Autodesk NLM (FLEXlm)
kme-trap-port         2081   KME PRINTER TRAP PORT
infowave              2082   Infowave Mobility Server
radsec                2083   Secure Radius Service
gnunet                2086   GNUnet
eli                   2087   ELI - Event Logging Integration
nbx-ser               2095   NBX SER
nbx-dir               2096   NBX DIR
h2250-annex-g         2099   H.225.0 Annex G
amiganetfs            2100   Amiga Network Filesystem
rtcm-sc104            2101
zephyr-clt            2103   Zephyr serv-hm connection
zephyr-hm             2104   Zephyr hostmanager
eklogin               2105   Kerberos (v4) encrypted rlogin
ekshell               2106   Kerberos (v4) encrypted rshell
msmq-mgmt             2107   Microsoft Message Queuing
rkinit                2108   Kerberos (v4) remote initialization
kx                    2111   X over kerberos
kip                   2112   IP over kerberos
kdm                   2115   Key Distribution Manager
gsigatekeeper         2119   GSIGATEKEEPER
kauth                 2120   Remote kauth
ccproxy-ftp           2121   CCProxy FTP Proxy
elatelink             2124   ELATELINK
pktcable-cops         2126   PktCable-COPS
avenue                2134   AVENUE
gris                  2135   Grid Resource Information Server
tdmoip                2142   TDM OVER IP
lv-ffx                2144   Live Vault Fast Object Transfer
veritas-ucl           2148   Veritas Universal Communication Layer
dynamic3d             2150   DYNAMIC3D
apc-2160              2160   APC 2160
apc-agent             2161   American Power Conversion
eyetv                 2170   EyeTV Server Port
vmrdp                 2179   Microsoft RDP for virtual machines
ssmc                  2187   Sepehr System Management Control
tivoconnect           2190   TiVoConnect Beacon
tvbus                 2191   TvBus Messaging
mnp-exchange          2197   MNP data exchange
ici                   2200   ICI
ats                   2201   Advanced Training System Program
b2-runtime            2203   b2 Runtime Protocol
EtherNet/IP-1         2222   EtherNet/IP I/O
efi-mg                2224   Easy Flexible Internet/Multiplayer Games
ivs-video             2232   IVS Video default
ivsd                  2241   IVS Daemon
remote-collab         2250
dif-port              2251   Distributed Framework Port
dtv-chan-req          2253   DTV Channel Request
apc-2260              2260   APC 2260
comotionmaster        2261   CoMotion Master Server
comotionback          2262   CoMotion Backup Server
apx500api-2           2265   Audio Precision Apx500 API Port 2
mikey                 2269   MIKEY
starschool            2270   starSchool
mmcals                2271   Secure Meeting Maker Scheduling
lnvpoller             2280   LNVPOLLER
netml                 2288   NETML
eapsp                 2291   EPSON Advanced Printer Share Protocol
mib-streaming         2292   Sonus Element Management Services
cvmmon                2300   CVMMON
compaqdiag            2301   Compaq remote diagnostic/management
binderysupport        2302   Bindery Support
attachmate-uts        2304   Attachmate UTS
pehelp                2307
wanscaler             2312   WANScaler Communication Service
iapp                  2313   IAPP (Inter Access Point Protocol)
3d-nfsd               2323
ansysli               2325   ANSYS Licensing Interconnect
idcp                  2326   IDCP
tscchat               2330   TSCCHAT
ace-proxy             2335   ACE Proxy
wrs_registry          2340   WRS Registry
qip-login             2366
worldwire             2371   Compaq WorldWire Port
lanmessenger          2372   LanMessenger
compaq-https          2381   Compaq HTTPS
ms-olap3              2382
ms-olap4              2383   MS OLAP 4
3com-net-mgmt         2391   3COM Net Management
ms-olap1              2393   SQL Server Downlevel OLAP Client Support
ms-olap2              2394   SQL Server Downlevel OLAP Client Support
fmpro-fdal            2399   FileMaker, Inc. - Data Access Layer
cvspserver            2401   CVS network server
cas                   2418
fjitsuappmgr          2425   Fujitsu App Manager
venus                 2430
venus-se              2431
codasrv               2432
codasrv-se            2433
optilogic             2435   OptiLogic
topx                  2436   TOP/X
msp                   2438   MSP
sybasedbsynch         2439   SybaseDBSynch
ratl                  2449   RATL
altav-remmgt          2456
lsi-raid-mgmt         2463   LSI RAID Management
c3                    2472   C3
groove                2492   GROOVE
rtsserv               2500   Resource Tracking system server
rtsclient             2501   Resource Tracking system client
ppcontrol             2505   PowerPlay Control
windb                 2522   WinDb
ms-v-worlds           2525   MS V-Worlds
ito-e-gui             2531   ITO-E GUI
ovtopmd               2532   OVTOPMD
ads                   2550   ADS
isg-uda-server        2551   ISG UDA Server
nicetec-mgmt          2557
pclemultimedia        2558   PCLE Multi Media
hp-3000-telnet        2564   HP 3000 NS/VT block mode telnet
clp                   2567   Cisco Line Protocol
tributary             2580   Tributary
mon                   2583   MON
cyaserv               2584
citriximaclient       2598   Citrix MA Client
zebrasrv              2600   zebra service
zebra                 2601   zebra vty
ripd                  2602   RIPd vty
ospfd                 2604   OSPFd vty
bgpd                  2605   BGPd vty
netmon                2606   Dell Netmon
connection            2607   Dell Connection
wag-service           2608   Wag Service
metricadbc            2622   MetricaDBC
lmdp                  2623   LMDP
webster               2627   Network dictionary
dict                  2628   Dictionary service
sitaradir             2631   Sitara Dir
sybase                2638   Sybase database
travsoft-ipx-t        2644   Travsoft IPX Tunnel
itinternet            2691   ITInternet ISM Server
tqdata                2700
sms-rcinfo            2701
sms-xfer              2702
ncdmirroring          2706   NCD Mirroring
sso-service           2710   SSO Service
sso-control           2711   SSO Control
aocp                  2712   Axapta Object Communication Protocol
pn-requester          2717   PN REQUESTER
pn-requester2         2718   PN REQUESTER 2
watchdog-nt           2723   WatchDog NT Protocol
msolap-ptp2           2725   SQL Analysis Server
sqdr                  2728   SQDR
ccs-software          2734   CCS Software
listen                2766   System V listener port
acc-raid              2800   ACC RAID
dvr-esm               2804   March Networks Digital Video Recorders
cspuni                2806
corbaloc              2809   Corba
gsiftp                2811   GSI FTP
atmtcp                2812
aimpp-port-req        2847   AIMPP Port Req
metaconsole           2850   MetaConsole
icslap                2869   UPnP Device Host, SSDP Discovery Service
dxmessagebase2        2875   DX Message Base Transport Protocol
ndtp                  2882   NDTP
spcsdlobby            2888   SPCSDLOBBY
rsom                  2889   RSOM
appliance-cfg         2898   APPLIANCE-CFG
allstorcns            2901   ALLSTORCNS
netaspi               2902   NET ASPI
extensisportfolio     2903   Portfolio Server by Extensis Product Group
mao                   2908
funk-dialout          2909   Funk Dialout
tdaccess              2910   TDAccess
roboeda               2920   roboEDA
amx-weblinx           2930   AMX-WEBLINX
jmact5                2957   JAMCT5
jmact6                2958   JAMCT6
symantec-av           2967   Symantec AntiVirus (rtvscan.exe)
enpp                  2968   ENPP
svnetworks            2973   SV Networks
hpidsadmin            2984   HPIDSADMIN
identify              2987
hippad                2988   HIPPA Reporting Protocol
wkstn-mon             2991   WKSTN-MON
rebol                 2997   REBOL
iss-realsec           2998   ISS RealSecure IDS Remote Console Admin port
ppp                   3000   User-level ppp daemon, or chili!soft asp
nessus                3001   Nessus Security Scanner Daemon or chili!soft asp
exlm-agent            3002   EXLM Agent
cgms                  3003   CGMS
deslogin              3005   encrypted symmetric telnet/login
deslogind             3006
lotusmtap             3007   Lotus Mail Tracking Agent Protocol
trusted-web           3011   Trusted Web
gilatskysurfer        3013   Gilat Sky Surfer
broker_service        3014   Broker Service
event_listener        3017   Event Listener
magicnotes            3023
slnp                  3025   SLNP (Simple Library Network Protocol)
arepa-cas             3030   Arepa Cas
eppc                  3031   Remote AppleEvents/PPC Toolbox
slnp                  3045   SLNP (Simple Library Network Protocol)
cfs                   3049   cryptographic file system (nfs) (proposed)
gds_db                3050
powerchute            3052
goahead-fldup         3057   GoAhead FldUp
ncacn-ip-tcp          3062
ncadg-ip-udp          3063
dnet-tstproxy         3064   distributed.net proxy test port
csd-mgmt-port         3071   ContinuStor Manager Port
orbix-loc-ssl         3077   Orbix 2000 Locator SSL
stm_pproc             3080
sj3                   3086   SJ3 (kanji input)
ptk-alink             3089   ParaTek Agent Linking
slslavemon            3102   SoftlinK Slave Mon Port
autocuesmi            3103   Autocue SMI Protocol
pkagent               3118   PKAgent
d2000kernel           3119   D2000 Kernel Port
squid-http            3128
vmodem                3141
bears-02              3146
sflm                  3162   SFLM
nowcontact            3167   Now Contact Public Server
poweronnud            3168   Now Up-to-Date Public Server
csvr-proxy            3190   ConServR Proxy
tick-port             3200   Press-sense Tick Port
flamenco-proxy        3210   Flamenco Networks Proxy
avsecuremgmt          3211   Avocent Secure Management
xnm-ssl               3220   XML NM over SSL
xnm-clear-text        3221   XML NM over TCP
triomotion            3240   Trio Motion Control Port
iscsi                 3260   iSCSI
winshadow             3261   winShadow
ecolor-imager         3263   E-Color Enterprise Imager
ccmail                3264   cc:mail/lotus
globalcatLDAP         3268   Global Catalog LDAP
globalcatLDAPssl      3269   Global Catalog LDAP over ssl
vs-server             3280   VS Server
sysopt                3281   SYSOPT
netassistant          3283   Apple Remote Desktop Net Assistant
sah-lm                3291   S A Holditch & Associates - LM
meetingmaker          3292   Meeting maker time management software
saprouter             3299   SAProuter
opsession-srvr        3304   OP Session Server
mysql                 3306   mySQL
opsession-prxy        3307   OP Session Proxy
dyna-access           3310   Dyna Access
mcns-tel-ret          3311   MCNS Tel Ret
sdt-lmd               3319   SDT License Manager
active-net            3322   Active Networks
active-net            3323   Active Networks
active-net            3324   Active Networks
active-net            3325   Active Networks
dec-notes             3333   DEC Notes
directv-web           3334   Direct TV Webcasting
btrieve               3351   Btrieve port
dj-ilm                3362   DJ ILM
nati-vi-server        3363   NATI Vi Server
contentserver         3365   Content Server
satvid-datalnk        3367   Satellite Video Data Link
satvid-datalnk        3368   Satellite Video Data Link
satvid-datalnk        3369   Satellite Video Data Link
satvid-datalnk        3370   Satellite Video Data Link
satvid-datalnk        3371   Satellite Video Data Link
msdtc                 3372   MS distributed transaction coordinator
cluster-disc          3374   Cluster Disc
cdbroker              3376   CD Broker
cbserver              3388   CB Server
ms-wbt-server         3389   Microsoft Remote Display Protocol
dsc                   3390   Distributed Service Coordinator
printer_agent         3396   Printer Agent
saposs                3397   SAP Oss
sapcomm               3398   SAPcomm
sapeps                3399   SAP EPS
csms2                 3400   CSMS2
networklenss          3410   NetworkLens SSL Event
wip-port              3414   BroadCloud WIP Port
bcinameservice        3415   BCI Name Service
softaudit             3419   Isogon SoftAudit
bmap                  3421   Bull Apprise portmapper
agps-port             3425   AGPS Access Port
ssdispatch            3430   Scott Studios Dispatch
hri-port              3439   HRI Interface Port
ov-nnm-websrv         3443   OpenView Network Node Manager WEB Server
vat                   3456   VAT default data
vat-control           3457   VAT default control
nppmp                 3476   NVIDIA Mgmt Protocol
twrpc                 3479   2Wire RPC
slim-devices          3483   Slim Devices Protocol
celatalk              3485   CelaTalk
ifsf-hb-port          3486   IFSF Heartbeat Port
nut                   3493   Network UPS Tools
ipether232port        3497   ipEther232Port
lsp-ping              3503   MPLS LSP-echo Port
ccmcomm               3505   CCM communications port
apc-3506              3506   APC 3506
webmail-2             3511   WebMail/2
arcpd                 3513   Adaptec Remote Protocol
must-p2p              3514   MUST Peer to Peer
must-backplane        3515   MUST Backplane
802-11-iapp           3517   IEEE 802.11 WLANs WG IAPP
nvmsgd                3519   Netvion Messenger Port
galileolog            3520   Netvion Galileo Log Port
starquiz-port         3526   starQuiz Port
beserver-msg-q        3527   VERITAS Backup Exec Server
gf                    3530   Grid Friendly
peerenabler           3531   P2PNetworking/PeerEnabler protocol
raven-rmp             3532   Raven Remote Management Control
apcupsd               3551   Apcupsd Information Port
config-port           3577   Configuration Port
nati-svrloc           3580   NATI-ServiceLocator
emprise-lsc           3586   License Server Console
quasar-server         3599   Quasar Accounting Server
trap-daemon           3600   text relay-answer
infiniswitchcl        3602   InfiniSwitch Mgr Client
int-rcv-cntrl         3603   Integrated Rcvr Control
ep-nsp                3621   EPSON Network Screen Port
ff-lr-port            3622   FF LAN Redundancy Port
distccd               3632   Distributed compiler daemon
servistaitsm          3636   SerVistaITSM
scservp               3637   Customer Service Port
vxcrnbuport           3652   VxCR NBU Default Port
tsp                   3653   Tunnel Setup Protocol
abatjss               3656   ActiveBatch Job Scheduler
ps-ams                3658   PlayStation AMS (Secure)
apple-sasl            3659   Apple SASL
dtp                   3663   DIRECWAY Tunnel Protocol
casanswmgmt           3669   CA SAN Switch Management
smile                 3670   SMILE TCP/UDP Interface
lispworks-orb         3672   LispWorks ORB
npds-tracker          3680   NPDS Tracker
bts-x73               3681   BTS X73 Port
bmc-ea                3683   BMC EDV/EA
faxstfx-port          3684   FAXstfX
rendezvous            3689   Rendezvous Zeroconf (used by Apple/iTunes)
svn                   3690   Subversion
nw-license            3697   NavisWorks License System
lrs-paging            3700   LRS NetPage
adobeserver-3         3703   Adobe Server 3
sentinel-ent          3712   Sentinel Enterprise
e-woa                 3728   Ericsson Web on Air
smap                  3731   Service Manager
xpanel                3737   XPanel Daemon
cst-port              3742   CST - Configuration & Service Tracker
cimtrak               3749   CimTrak
rtraceroute           3765   Remote Traceroute
bfd-control           3784   BFD Control Protocol
fintrx                3787   Fintrx
isrp-port             3788   SPACEWAY Routing port
quickbooksrds         3790   QuickBooks RDS
sitewatch             3792   e-Watch Corporation SiteWatch
dcsoftware            3793   DataCore Software
myblast               3795   myBLAST Mekentosj port
spw-dialer            3796   Spaceway Dialer
minilock              3798   Minilock
radius-dynauth        3799   RADIUS Dynamic Authorization
pwgpsi                3800   Print Services Interface
ibm-mgr               3801   ibm manager service
soniqsync             3803   SoniqSync
wsmlb                 3806   Remote System Manager
sun-as-iiops-ca       3808   Sun App Svr-IIOPClntAuth
apocd                 3809   Java Desktop System Configuration Agent
wlanauth              3810   WLAN AS server
amp                   3811   AMP
neto-wol-server       3812   netO WOL Server
rap-ip                3813   Rhapsody Interface Protocol
neto-dcs              3814   netO DCS
tapeware              3817   Yosemite Tech Tapeware
scp                   3820   Siemens AuD SCP
acp-conduit           3823   Compute Pool Conduit
acp-policy            3824   Compute Pool Policy
ffserver              3825   Antera FlowFusion Process Simulation
wormux                3826   Wormux server
netmpi                3827   Netadmin Systems MPI service
neteh                 3828   Netadmin Systems Event Handler
cernsysmgmtagt        3830   Cerner System Management Agent
dvapps                3831   Docsvault Application Service
mkm-discovery         3837   MARKEM Auto-Discovery
amx-rms               3839   AMX Resource Management Suite
nhci                  3842   NHCI status port
an-pcp                3846   Astare Network PCP
msfw-control          3847   MS Firewall Control
item                  3848   IT Environmental Monitor
spw-dnspreload        3849   SPACEWAY DNS Preload
qtms-bootstrap        3850   QTMS Bootstrap Protocol
spectraport           3851   SpectraTalk Port
sse-app-config        3852   SSE App Configuration
sscan                 3853   SONY scanning protocol
informer              3856   INFORMER
nav-port              3859   Navini Port
sasp                  3860   Server/Application State Protocol (SASP)
asap-tcp              3863   RSerPool ASAP (TCP)
diameter              3868   DIAMETER
ovsam-mgmt            3869   hp OVSAM MgmtServer Disco
ovsam-d-agent         3870   hp OVSAM HostAgent Disco
avocent-adsap         3871   Avocent DS Authorization
oem-agent             3872   OEM Agent
dl_agent              3876   DirectoryLockdown Agent
fotogcad              3878   FotoG CAD interface
appss-lm              3879   appss license manager
igrs                  3880   IGRS
msdts1                3882   DTS Service Port
ciphire-serv          3888   Ciphire Services
dandv-tester          3889   D and V Tester Control Port
ndsconnect            3890   Niche Data Server Connect
sdo-ssh               3897   Simple Distributed Objects over SSH
itv-control           3899   ITV Port
udt_os                3900   Unidata UDT OS
nimsh                 3901   NIM Service Handler
nimaux                3902   NIMsh Auxiliary Port
omnilink-port         3904   Arnet Omnilink Port
mupdate               3905   Mailbox Update (MUPDATE) protocol
topovista-data        3906   TopoVista elevation data
imoguia-port          3907   Imoguia Port
hppronetman           3908   HP Procurve NetManagement
surfcontrolcpa        3909   SurfControl CPA
prnstatus             3911   Printer Status Port
listcrt-port          3913   ListCREATOR Port
listcrt-port-2        3914   ListCREATOR Port 2
agcat                 3915   Auto-Graphics Cataloging
wysdmc                3916   WysDM Controller
pktcablemmcops        3918   PacketCableMultimediaCOPS
hyperip               3919   HyperIP
exasoftport1          3920   Exasoft IP Port
sor-update            3922   Soronti Update Port
symb-sb-port          3923   Symbian Service Broker
netboot-pxe           3928   PXE NetBoot Manager
smauth-port           3929   AMS Port
syam-webserver        3930   Syam Web Server Port
msr-plugin-port       3931   MSR Plugin Port
sdp-portmapper        3935   SDP Port Mapper Protocol
mailprox              3936   Mailprox
dvbservdsc            3937   DVB Service Discovery
xecp-node             3940   XeCP Node Service
homeportal-web        3941   Home Portal Web Server
tig                   3943   TetraNode Ip Gateway
sops                  3944   S-Ops Management
emcads                3945   EMCADS Server Port
backupedge            3946   BackupEDGE Server
apdap                 3948   Anton Paar Device Administration Protocol
drip                  3949   Dynamic Routing Information Protocol
i3-sessionmgr         3952   I3 Session Manager
gvcp                  3956   GigE Vision Control
mqe-broker            3957   MQEnterprise Broker
proaxess              3961   ProAxess Server
sbi-agent             3962   SBI Agent Protocol
thrp                  3963   Teran Hybrid Routing Protocol
sasggprs              3964   SASG GPRS
ppsms                 3967   PPS Message Service
ianywhere-dbns        3968   iAnywhere DBNS
landmarks             3969   Landmark Messages
lanrevserver          3971   LANrev Server
iconp                 3972   ict-control Protocol
airshot               3975   Air Shot
smwan                 3979   Smith Micro Wide Area Network Service
acms                  3980   Aircraft Cabin Management System
starfish              3981   Starfish System Admin
eis                   3982   ESRI Image Server
eisp                  3983   ESRI Image Service
mapper-nodemgr        3984   MAPPER network node manager
mapper-mapethd        3985   MAPPER TCP/IP server
mapper-ws_ethd        3986   MAPPER workstation server
bv-queryengine        3989   BindView-Query Engine
bv-is                 3990   BindView-IS
bv-smcsrv             3991   BindView-SMCServer
bv-ds                 3992   BindView-DirectoryServer
bv-agent              3993   BindView-Agent
iss-mgmt-ssl          3995   ISS Management Svcs SSL
abcsoftware           3996   abcsoftware-01
agentsease-db         3997   aes_db
dnx                   3998   Distributed Nagios Executor Service
remoteanything        3999   neoworx remote-anything slave file browser
remoteanything        4000   neoworx remote-anything slave remote control
newoak                4001   NewOak
mlchat-proxy          4002   mlnet - MLChat P2P chat proxy
pxc-splr-ft           4003
pxc-roid              4004
pxc-pin               4005
pxc-spvr              4006
pxc-splr              4007
netcheque             4008   NetCheque accounting
chimera-hwm           4009   Chimera HWM
samsung-unidex        4010   Samsung Unidex
talarian-mcast2       4016   Talarian Mcast
trap                  4020   TRAP Port
dnox                  4022   DNOX
tnp1-port             4024   TNP1 User Port
partimage             4025   Partition Image Port
ip-qsig               4029   IP Q signaling protocol
wap-push-http         4035   WAP Push OTA-HTTP port
wap-push-https        4036   WAP Push OTA-HTTP secure
fazzt-admin           4039   Fazzt Administration
yo-main               4040   Yo.net main service
lockd                 4045
lms                   4056   Location Message Service
kingfisher            4058   Kingfisher protocol
avanti_cdp            4065   Avanti Common Data
lorica-in             4080   Lorica inside facing
applusservice         4087   APplus Service
omasgport             4090   OMA BCAST Service Guide
bre                   4096   BRE (Bridge Relay Element)
igo-incognito         4100   IGo Incognito Data Port
brlp-0                4101   Braille protocol
xgrid                 4111   Xgrid
apple-vpns-rp         4112   Apple VPN Server Reporting Protocol
aipn-reg              4113   AIPN LS Registration
netscript             4118   Netadmin Systems NETscript service
assuria-slm           4119   Assuria Log Manager
e-builder             4121   e-Builder Application Communication
rww                   4125   Microsoft Remote Web Workplace
ddrepl                4126   Data Domain Replication Service
nuauth                4129   NuFW authentication protocol
nuts_dem              4132   NUTS Daemon
nuts_bootp            4133   NUTS Bootp Server
cl-db-attach          4135   Classic Line Database Server Attach
oirtgsvc              4141   Workflow Server
oidsr                 4143   Document Replication
wincim                4144   pc windows compuserve.com protocol
vrxpservman           4147   Multum Service Manager
stat-cc               4158   STAT Command Center
omscontact            4161   OMS Contact
silverpeakcomm        4164   Silver Peak Communication Protocol
sieve                 4190   ManageSieve Protocol
azeti                 4192   Azeti Agent Service
eims-admin            4199   Eudora Internet Mail Service (EIMS) admin
vrml-multi-use        4200   VRML Multi User Systems
vrml-multi-use        4206   VRML Multi User Systems
vrml-multi-use        4220   VRML Multi User Systems
xtell                 4224   Xtell messenging server
vrml-multi-use        4234   VRML Multi User Systems
vrml-multi-use        4242   VRML Multi User Systems
vrml-multi-use        4252   VRML Multi User Systems
vrml-multi-use        4262   VRML Multi User Systems
vrml-multi-use        4279   VRML Multi User Systems
vrml-multi-use        4294   VRML Multi User Systems
vrml-multi-use        4297   VRML Multi User Systems
vrml-multi-use        4298   VRML Multi User Systems
corelccam             4300   Corel CCam
d-data-control        4302   Diagnostic Data Control
rwhois                4321   Remote Who Is
geognosisman          4325   Cadcorp GeognoSIS Manager Service
jaxer-manager         4328   Jaxer Manager Command Protocol
msql                  4333   mini-sql server
lisp-cons             4342   LISP-CONS Control
unicall               4343
qsnet-workst          4355   QSNet Workstation
qsnet-assist          4356   QSNet Assistant
qsnet-cond            4357   QSNet Conductor
qsnet-nucl            4358   QSNet Nucleus
epmd                  4369   Erlang Port Mapper Daemon
psi-ptt               4374   PSI Push-to-Talk Protocol
tolteces              4375   Toltec EasyShare
bip                   4376   BioAPI Interworking
ds-srvr               4401   ASIGRA Televaulting DS-System Service
nacagent              4407   Network Access Control Agent
rsqlserver            4430   REAL SQL Server
saris                 4442   Saris
pharos                4443
krb524                4444   Kerberos 5 to 4 ticket xlator
upnotifyp             4445   UPNOTIFYP
n1-fwp                4446   N1-FWP
n1-rmgmt              4447   N1-RMGMT
privatewire           4449   PrivateWire
nssagentmgr           4454   NSS Agent Manager
proxy-plus            4480   Proxy+ HTTP proxy port
sae-urn               4500
worldscores           4545   WorldScores
gds-adppiw-db         4550   Perman I Interbase Server
rsip                  4555   RSIP Port
fax                   4557   FlexFax FAX transmission service
hylafax               4559   HylaFAX client-server protocol
tram                  4567   TRAM
a17-an-an             4599   A17 (AN-AN)
piranha1              4600   Piranha1
piranha2              4601   Piranha2
mtsserver             4602   EAX MTS Server
playsta2-app          4658   PlayStation2 App Port
mosmig                4660   OpenMOSix MIGrates local processes
edonkey               4662   eDonkey file sharing (Donkey)
contclientms          4665   Container Client Message Service
rfa                   4672   remote file access server
nst                   4687   Network Scanner Tool FTP
altovacentral         4689   Altova DatabaseCentral
netxms-agent          4700   NetXMS Agent
pulseaudio            4713   Pulse Audio UNIX sound framework
fmp                   4745   Funambol Mobile Push
iims                  4800   Icona Instant Messenging System
appserv-http          4848   App Server - Admin HTTP
radmin                4899   Radmin remote PC control software
hfcs                  4900   HyperFileSQL Client/Server Database Engine
lutap                 4912   Technicolor LUT Access Protocol
munin                 4949   Munin Graphing Framework
maybe-veritas         4987
maybe-veritas         4998
hfcs-manager          4999   HyperFileSQL Client/Server Database Engine Mgr.
upnp                  5000   Universal PnP, also Free Internet Chess Server
commplex-link         5001
rfe                   5002   Radio Free Ethernet
filemaker             5003   Filemaker Server
avt-profile-1         5004   RTP media data
avt-profile-2         5005   RTP control protocol
airport-admin         5009   Apple AirPort WAP Administration
telelpathstart        5010
telelpathattack       5011
nsp                   5012   NetOnTap Service
fmpro-v6              5013   FileMaker, Inc. - Proprietary transport
fmwp                  5015   FileMaker, Inc. - Web publishing
zenginkyo-1           5020
zenginkyo-2           5021
htuilsrv              5023   Htuil Server for PLD2
surfpass              5030   SurfPass
mmcc                  5050   multimedia conference control tool
ida-agent             5051   Symantec Intruder Alert
ita-manager           5052   ITA Manager
rlm                   5053   RLM License Server
rlm-admin             5054   RLM administrative interface
unot                  5055   UNOT
sip                   5060   Session Initiation Protocol (SIP)
sip-tls               5061   SIP-TLS
csrpc                 5063   centrify secure RPC
stanag-5066           5066   STANAG-5066-SUBNET-INTF
vtsas                 5070   VersaTrans Server Agent Service
alesquery             5074   ALES Query
onscreen              5080   OnScreen Data Collection Service
sdl-ets               5081   SDL - Ent Trans Server
admd                  5100   (chili!soft asp admin port) or Yahoo pager
admdog                5101   (chili!soft asp)
admeng                5102   (chili!soft asp)
taep-as-svc           5111   TAEP AS service
ev-services           5114   Enterprise Vault Services
nbt-pc                5133   Policy Commander
ctsd                  5137   MyCTS server port
rmonitor_secure       5145
esri_sde              5151   ESRI SDE Instance
sde-discovery         5152   ESRI SDE Instance Discovery
aol                   5190   America-Online.  Also can be used by ICQ
aol-1                 5191   AmericaOnline1
aol-3                 5193   AmericaOnline3
targus-getdata        5200   TARGUS GetData
targus-getdata1       5201   TARGUS GetData 1
targus-getdata2       5202   TARGUS GetData 2
3exmp                 5221   3eTI Extensible Management Protocol for OAMP
xmpp-client           5222   XMPP Client Connection
hpvirtgrp             5223   HP Virtual Machine Group Management
hp-server             5225   HP Server
hp-status             5226   HP Status
sgi-dgl               5232   SGI Distributed Graphics
eenet                 5234   EEnet communications
galaxy-network        5235   Galaxy Network Service
soagateway            5250   soaGateway
movaz-ssc             5252   Movaz SSC
xmpp-server           5269   XMPP Server Connection
xmpp-bosh             5280   Bidirectional-streams Over Synchronous HTTP
presence              5298   XMPP Link-Local Messaging
hacl-hb               5300   HA cluster heartbeat
hacl-gs               5301   HA cluster general services
hacl-cfg              5302   HA cluster configuration
hacl-probe            5303   HA cluster probing
cfengine              5308
mdns                  5353   Multicast DNS
wsdapi                5357   Web Services for Devices
pcduo-old             5400   RemCon PC-Duo - old port
pcduo                 5405   RemCon PC-Duo - new port
statusd               5414   StatusD
virtualuser           5423   VIRTUALUSER
park-agent            5431
postgresql            5432   PostgreSQL database server
pyrrho                5433   Pyrrho DBMS
connect-proxy         5490   Many HTTP CONNECT proxies
hotline               5500   Hotline file sharing client/server
fcp-addr-srvr2        5501
fcp-srvr-inst1        5502
secureidprop          5510   ACE/Server services
sdlog                 5520   ACE/Server services
sdserv                5530   ACE/Server services
sdadmind              5550   ACE/Server services
sgi-eventmond         5553   SGI Eventmond Port
sgi-esphttp           5554   SGI ESP HTTP
freeciv               5555
farenet               5557   Sandlab FARENET
isqlplus              5560   Oracle web enabled SQL interface (version 10g+)
westec-connect        5566   Westec Connect
tmosms0               5580   T-Mobile SMS Protocol Message 0
tmosms1               5581   T-Mobile SMS Protocol Message 1
pcanywheredata        5631
pcanywherestat        5632
beorl                 5633   BE Operations Request Listener
nrpe                  5666   Nagios NRPE
amqp                  5672   AMQP
rrac                  5678   Remote Replication Agent Connection
activesync            5679   Microsoft ActiveSync PDY synchronization
canna                 5680   Canna (Japanese Input)
proshareaudio         5713   proshare conf audio
prosharevideo         5714   proshare conf video
prosharenotify        5717   proshare conf notify
dpm                   5718   DPM Communication Server
dtpt                  5721   Desktop Passthru Service
msdfsr                5722   Microsoft DFS Replication Service
omhs                  5723   Operations Manager - Health Service
unieng                5730   Steltor's calendar access
vnc-http              5800   Virtual Network Computer HTTP Access, display 0
vnc-http-1            5801   Virtual Network Computer HTTP Access, display 1
vnc-http-2            5802   Virtual Network Computer HTTP Access, display 2
vnc-http-3            5803   Virtual Network Computer HTTP Access, display 3
spt-automation        5814   Support Automation
wherehoo              5859   WHEREHOO
vnc                   5900   Virtual Network Computer display 0
vnc-1                 5901   Virtual Network Computer display 1
vnc-2                 5902   Virtual Network Computer display 2
vnc-3                 5903   Virtual Network Computer display 3
cm                    5910   Context Management
cpdlc                 5911   Controller Pilot Data Link Communication
fis                   5912   Flight Information Services
indy                  5963   Indy Application Server
mppolicy-v5           5968
mppolicy-mgr          5969
ncd-pref-tcp          5977   NCD preferences tcp port
ncd-diag-tcp          5978   NCD diagnostic tcp port
wsman                 5985   WBEM WS-Management HTTP
wsmans                5986   WBEM WS-Management HTTP over TLS/SSL
wbem-rmi              5987   WBEM RMI
wbem-http             5988   WBEM CIM-XML (HTTP)
wbem-https            5989   WBEM CIM-XML (HTTPS)
ncd-pref              5997   NCD preferences telnet port
ncd-diag              5998   NCD diagnostic telnet port
ncd-conf              5999   NCD configuration telnet port
X11                   6000   X Window server
X11:1                 6001   X Window server
X11:2                 6002   X Window server
X11:3                 6003   X Window server
X11:4                 6004   X Window server
X11:5                 6005   X Window server
X11:6                 6006   X Window server
X11:7                 6007   X Window server
X11:8                 6008   X Window server
X11:9                 6009   X Window server
x11                   6010   X Window System
x11                   6015   X Window System
xmail-ctrl            6017   XMail CTRL server
x11                   6021   X Window System
x11                   6025   X Window System
x11                   6030   X Window System
arcserve              6050   ARCserve agent
x11                   6051   X Window System
x11                   6052   X Window System
x11                   6055   X Window System
X11:59                6059   X Window server
x11                   6060   X Window System
x11                   6062   X Window System
x11                   6063   X Window System
winpharaoh            6065   WinPharaoh
gsmp                  6068   GSMP
konspire2b            6085   konspire2b p2p network
synchronet-db         6100   SynchroNet-db
backupexec            6101   Backup Exec UNIX and 95/98/ME Aent
RETS-or-BackupExec    6103   Backup Exec Agent Accelerator and Remote Agent
isdninfo              6105
isdninfo              6106   i4lmond
softcm                6110   HP SoftBench CM
spc                   6111   HP SoftBench Sub-Process Control
dtspc                 6112   CDE subprocess control
dayliteserver         6113   Daylite Server
xic                   6115   Xic IPC Service
backup-express        6123   Backup Express
meta-corp             6141   Meta Corporation License Manager
aspentec-lm           6142   Aspen Technology License Manager
watershed-lm          6143   Watershed License Manager
statsci2-lm           6145   StatSci License Manager - 2
lonewolf-lm           6146   Lone Wolf Systems License Manager
montage-lm            6147   Montage License Manager
patrol-ism            6161   PATROL Internet Srv Mgr
radmind               6222   Radmind protocol
tl1-raw-ssl           6251   TL1 Raw Over SSL/TLS
gnutella              6346   Gnutella file sharing protocol
gnutella2             6347   Gnutella2 file sharing protocol
adap                  6350   App Discovery and Access Protocol
clariion-evr01        6389
crystalreports        6400   Seagate Crystal Reports
crystalenterprise     6401   Seagate Crystal Enterprise
servicetags           6481   Service Tags
boks                  6500   BoKS Master
netop-rc              6502   NetOp Remote Control
boks_clntd            6503   BoKS Clntd
mcer-port             6510   MCER Port
mythtv                6543
mythtv                6544
powerchuteplus        6547
powerchuteplus        6548
fg-sysupdate          6550
sane-port             6566   SANE Control Port
esp                   6567   eSilo Storage Protocol
affiliate             6579   Affiliate
parsec-master         6580   Parsec Masterserver
analogx               6588   AnalogX HTTP proxy port
mshvlm                6600   Microsoft Hyper-V Live Migration
afesc-mc              6628   AFE Stock Channel M/C
radmind               6662   Radmind protocol (deprecated)
irc                   6665   Internet Relay Chat
irc                   6666   internet relay chat server
irc                   6667   Internet Relay Chat
irc                   6668   Internet Relay Chat
irc                   6669   Internet Relay Chat
irc                   6670   Internet Relay Chat
tsa                   6689   Tofino Security Appliance
napster               6699   Napster File (MP3) sharing  software
carracho              6700   Carracho file sharing
carracho              6701   Carracho file sharing
smc-http              6788   SMC-HTTP
ibm-db2-admin         6789   IBM DB2
bittorrent-tracker    6881   BitTorrent tracker
muse                  6888   MUSE
jetstream             6901   Novell Jetstream messaging protocol
acmsoda               6969
afs3-fileserver       7000   file server itself, msdos
afs3-callback         7001   callbacks to cache managers
afs3-prserver         7002   users & groups database
afs3-vlserver         7003   volume location database
afs3-kaserver         7004   AFS/Kerberos authentication service
afs3-volser           7005   volume managment server
afs3-errors           7006   error interpretation service
afs3-bos              7007   basic overseer process
afs3-update           7008   server-to-server updater
afs3-rmtsys           7009   remote cache manager service
ups-onlinet           7010   onlinet uninterruptable power supplies
vmsvc                 7024   Vormetric service
vmsvc-2               7025   Vormetric Service II
realserver            7070
iwg1                  7071   IWGADTS Aircraft Housekeeping Message
empowerid             7080   EmpowerID Communication
lazy-ptop             7099
font-service          7100   X Font Service
elcn                  7101   Embedded Light Control Network
virprot-lm            7121   Virtual Prototypes License Manager
fodms                 7200   FODMS FLIP
dlip                  7201
watchme-7272          7272   WatchMe Monitoring 7272
openmanage            7273   Dell OpenManage
oma-dcdocbs           7278   OMA Dynamic Content Delivery over CBS
itactionserver2       7281   ITACTIONSERVER 2
swx                   7300   The Swiss Exchange
swx                   7320   The Swiss Exchange
swx                   7325   The Swiss Exchange
icb                   7326   Internet Citizen's Band
swx                   7345   The Swiss Exchange
rtps-discovery        7400   RTPS Discovery
rtps-dd-mt            7402   RTPS Data-Distribution Meta-Traffic
oracleas-https        7443   Oracle Application Server HTTPS
pythonds              7464   Python Documentation Server
silhouette            7500   Silhouette User
ovbus                 7501   HP OpenView Bus Daemon
qaz                   7597   Quaz trojan worm
soap-http             7627   SOAP Service Port
zen-pawn              7628   Primary Agent Work Notification
hddtemp               7634   A hard disk temperature monitoring daemon
imqbrokerd            7676   iMQ Broker Rendezvous
nitrogen              7725   Nitrogen Service
scriptview            7741   ScriptView Network
raqmon-pdu            7744   RAQMON PDU
cbt                   7777
interwise             7778   Interwise
office-tools          7789   Office Tools Pro Receive
asr                   7800   Apple Software Restore
mevent                7900   Multicast Event
qo-secure             7913   QuickObjects secure port
nsrexecd              7937   Legato NetWorker
lgtomapper            7938   Legato portmapper
irdmi2                7999   iRDMI2
http-alt              8000   A common alternative http port
vcom-tunnel           8001   VCOM Tunnel
teradataordbms        8002   Teradata ORDBMS
mcreport              8003   Mulberry Connect Reporting Service
mxi                   8005   MXI Generation II for z/OS
ajp12                 8007   Apache JServ Protocol 1.x
http                  8008   IBM HTTP server
ajp13                 8009   Apache JServ Protocol 1.3
xmpp                  8010   XMPP File Transfer
qbdb                  8019   QB DB Dynamic Port
ftp-proxy             8021   Common FTP proxy port
oa-system             8022
ca-audit-da           8025   CA Audit Distribution Agent
fs-agent              8042   FireScope Agent
senomix01             8052   Senomix Timesheets Server
slnp                  8076   SLNP (Simple Library Network Protocol)
http-proxy            8080   Common HTTP proxy/second web server port
blackice-icecap       8081   ICECap user console
blackice-alerts       8082   BlackIce Alerts sent to this port
us-srv                8083   Utilistor (Server)
d-s-n                 8086   Distributed SCADA Networking Rendezvous Port
simplifymedia         8087   Simplify Media SPP Protocol
radan-http            8088   Radan HTTP
sac                   8097   SAC Port Id
xprint-server         8100   Xprint Server
cp-cluster            8116   Check Point Clustering
privoxy               8118   Privoxy
polipo                8123   Polipo open source web proxy cache
sophos                8192   Sophos Remote Management System
sophos                8193   Sophos Remote Management System
sophos                8194   Sophos Remote Management System
trivnet1              8200   TRIVNET
trivnet2              8201   TRIVNET
blp3                  8292   Bloomberg professional
hiperscan-id          8293   Hiperscan Identification Service
blp4                  8294   Bloomberg intelligent client
tmi                   8300   Transport Management Interface
m2mservices           8383   M2m Services
cvd                   8400
sabarsd               8401
abarsd                8402
admind                8403
https-alt             8443   Common alternative https port
cisco-avp             8470   Cisco Address Validation Protocol
pim-port              8471   PIM over Reliable Transport
otv                   8472   Overlay Transport Virtualization (OTV)
noteshare             8474   AquaMinds NoteShare
fmtp                  8500   Flight Message Transfer Protocol
asterix               8600   Surveillance Data
sun-as-jmxrmi         8686   Sun App Server - JMX/RMI
ultraseek-http        8765   Ultraseek HTTP
apple-iphoto          8770   Apple iPhoto sharing
sunwebadmin           8800   Sun Web Server Admin Service
dxspider              8873   dxspider linking protocol
cddbp-alt             8880   CDDBP
sun-answerbook        8888   Sun Answerbook HTTP server
ddi-tcp-2             8889   Desktop Data TCP 1
seosload              8892   From the new Computer Associates eTrust ACX
ospf-lite             8899
jmb-cds1              8900   JMB-CDS 1
cumulus-admin         8954   Cumulus Admin Port
bctp                  8999   Brodos Crypto Trade Protocol
cslistener            9000   CSlistener
tor-orport            9001   Tor ORPort
dynamid               9002   DynamID authentication
pichat                9009   Pichat Server
sdr                   9010   Secure Data Replicator Protocol
tambora               9020   TAMBORA
panagolin-ident       9021   Pangolin Identification
paragent              9022   PrivateArk Remote Agent
tor-trans             9040   Tor TransPort
tor-socks             9050   Tor SocksPort
tor-control           9051   Tor ControlPort
glrpc                 9080   Groove GLRPC
aurora                9084   IBM AURORA Performance Visualizer
zeus-admin            9090   Zeus admin server
xmltec-xmlmail        9091
jetdirect             9100   HP JetDirect card
jetdirect             9101   HP JetDirect card
jetdirect             9102   HP JetDirect card or Bacula File Daemon
jetdirect             9103   HP JetDirect card
jetdirect             9104   HP JetDirect card
jetdirect             9105   HP JetDirect card
jetdirect             9106   HP JetDirect card
jetdirect             9107   HP JetDirect card
DragonIDSConsole      9111   Dragon IDS Console
dddp                  9131   Dynamic Device Discovery
ms-sql2000            9152
apani1                9160
apani2                9161
sun-as-jpda           9191   Sun AppSvr JPDA
wap-wsp               9200   WAP connectionless session services
wap-wsp-s             9202   WAP secure connectionless session service
wap-vcal-s            9207   WAP vCal Secure
oma-mlp               9210   OMA Mobile Location Protocol
oma-mlp-s             9211   OMA Mobile Location Protocol Secure
cumulus               9287   Cumulus
vrace                 9300   Virtual Racing Service
mpidcmgr              9343   MpIdcMgr
sec-t4net-srv         9400   Samsung Twain for Network Server
git                   9418   Git revision control system
tungsten-https        9443   WSO2 Tungsten HTTPS
wso2esb-console       9444   WSO2 ESB Administration Console HTTPS
ismserver             9500
man                   9535
ldgateway             9592   LANDesk Gateway
cba8                  9593   LANDesk Management Agent (cba8)
msgsys                9594   Message System
pds                   9595   Ping Discovery System
micromuse-ncpw        9600   MICROMUSE-NCPW
erunbook_agent        9616   eRunbook Agent
condor                9618   Condor Collector Service
odbcpathway           9628   ODBC Pathway Service
xmms2                 9667   Cross-platform Music Multiplexing System
client-wakeup         9694   T-Mobile Client Wakeup Message
board-roar            9700   Board M.I.T. Service
sapv1                 9875   Session Announcement v1
sd                    9876   Session Director
monkeycom             9898   MonkeyCom
iua                   9900   IUA
domaintime            9909
sype-transport        9911   SYPECom Transport Protocol
nping-echo            9929   Nping echo server mode
apc-9950              9950   APC 9950
nsesrvr               9988   Software Essentials Secure HTTP server
osm-appsrvr           9990   OSM Applet Server
issa                  9991   ISS System Scanner Agent
issc                  9992   ISS System Scanner Console
palace-4              9995   Palace-4
distinct32            9998   Distinct32
abyss                 9999   Abyss web server remote web management interface
snet-sensor-mgmt      10000  SecureNet Pro Sensor https management server
scp-config            10001  SCP Configuration
documentum            10002  EMC-Documentum Content Server Product
documentum_s          10003  EMC-Documentum Content Server Product
emcrmirccd            10004  EMC Replication Manager Client
stel                  10005  Secure telnet
mvs-capacity          10007  MVS Capacity
octopus               10008  Octopus Multiplexer
swdtp-sv              10009  Systemwalker Desktop Patrol
rxapi                 10010  ooRexx rxapi services
amandaidx             10082  Amanda indexing
amidxtape             10083  Amanda tape indexing
ezmeeting-2           10101  eZmeeting
netiq-endpt           10115  NetIQ Endpoint
qb-db-server          10160  QB Database Server
irisa                 11000  IRISA
metasys               11001  Metasys
vce                   11111  Viral Computing Environment (VCE)
pksd                  11371  PGP Public Key Server
sysinfo-sp            11967  SysInfo Service Protocol
cce4x                 12000  ClearCommerce Engine 4.x
entextnetwk           12001  IBM Enterprise Extender SNA COS Network Priority
entexthigh            12002  IBM Enterprise Extender SNA COS High Priority
dbisamserver1         12005  DBISAM Database Server - Regular
dbisamserver2         12006  DBISAM Database Server - Admin
nupaper-ss            12121  NuPaper Session Service
netbus                12345  NetBus backdoor trojan or Trend Micro Office Scan
netbus                12346  NetBus backdoor trojan
netbackup             13701  vmd           server
netbackup             13713  tl4d          server
netbackup             13714  tsdd          server
netbackup             13715  tshd          server
netbackup             13718  lmfcd         server
netbackup             13720  bprd          server
netbackup             13721  bpdbm         server
netbackup             13722  bpjava-msvc   client
vnetd                 13724  Veritas Network Utility
netbackup             13782  bpcd          client
netbackup             13783  vopied        client
scotty-ft             14000  SCOTTY High-Speed Filetransfer
sua                   14001  SUA
bo2k                  14141  Back Orifice 2K BoPeep mouse/keyboard input
hydap                 15000  Hypack Hydrographic Software Data Acquisition
bo2k                  15151  Back Orifice 2K BoPeep video output
bex-xr                15660  Backup Express Restore Server
fmsas                 16000  Administration Server Access
fmsascon              16001  Administration Server Connector
osxwebadmin           16080  Apple OS X WebAdmin
sun-sea-port          16161  Solaris SEA Port
overnet               16444  Overnet file sharing
newbay-snc-mc         16900  Newbay Mobile Client Update Service
amt-soap-http         16992  Intel(R) AMT SOAP/HTTP
amt-soap-https        16993  Intel(R) AMT SOAP/HTTPS
isode-dua             17007
kuang2                17300  Kuang2 backdoor
db-lsp                17500  Dropbox LanSync Protocol
biimenu               18000  Beckman Instruments, Inc.
opsec-cvp             18181  Check Point OPSEC
opsec-ufp             18182  Check Point OPSEC
opsec-sam             18183  Check Point OPSEC
opsec-lea             18184  Check Point OPSEC
opsec-ela             18187  Check Point OPSEC
gkrellm               19150  GKrellM remote system activity meter daemon
keysrvr               19283  Key Server for SASSAFRAS
keyshadow             19315  Key Shadow for SASSAFRAS
dnp                   20000  DNP
microsan              20001  MicroSAN
commtact-http         20002  Commtact HTTP
btx                   20005  xcept4
ipulse-ics            20222  iPulse-ICS
memcachedb            21201
dcap                  22125  dCache Access Protocol
gsidcap               22128  GSI dCache Access Protocol
wnn6                  22273  Wnn6 (Japanese input)
CodeMeter             22350  CodeMeter Standard
vocaltec-wconf        22555  Vocaltec Web Conference
binkp                 24554  BINKP
icl-twobase1          25000
icl-twobase2          25001
minecraft             25565  A video game
quake                 26000
wnn6_DS               26208  Wnn6 (Dserver)
flexlm0               27000  FlexLM license manager additional ports
flexlm1               27001  FlexLM license manager additional ports
flexlm2               27002  FlexLM license manager additional ports
flexlm3               27003  FlexLM license manager additional ports
flexlm5               27005  FlexLM license manager additional ports
flexlm7               27007  FlexLM license manager additional ports
flexlm9               27009  FlexLM license manager additional ports
flexlm10              27010  FlexLM license manager additional ports
subseven              27374  Subseven Windows trojan
Trinoo_Master         27665  Trinoo distributed attack tool
pago-services1        30001  Pago Services 1
Elite                 31337  Sometimes interesting stuff can be found here
boinc                 31416  BOINC Client Control
diagd                 31727
filenet-powsrm        32767  FileNet BPM WS-ReliableMessaging Client
filenet-tms           32768  Filenet TMS
filenet-rpc           32769  Filenet RPC
sometimes-rpc3        32770  Sometimes an RPC port on my Solaris box
sometimes-rpc5        32771  Sometimes an RPC port on my Solaris box (rusersd)
sometimes-rpc7        32772  Sometimes an RPC port on my Solaris box (status)
sometimes-rpc9        32773  Sometimes an RPC port on my Solaris box (rquotad)
sometimes-rpc11       32774  Sometimes an RPC port on my Solaris box (rusersd)
sometimes-rpc13       32775  Sometimes an RPC port on my Solaris box (status)
sometimes-rpc15       32776  Sometimes an RPC port on my Solaris box (sprayd)
sometimes-rpc17       32777  Sometimes an RPC port on my Solaris box (walld)
sometimes-rpc19       32778  Sometimes an RPC port on my Solaris box (rstatd)
sometimes-rpc21       32779  Sometimes an RPC port on my Solaris box
sometimes-rpc23       32780  Sometimes an RPC port on my Solaris box
sometimes-rpc25       32786  Sometimes an RPC port (mountd)
sometimes-rpc27       32787  Sometimes an RPC port (DMI Service Provider)
landesk-cba           38037
landesk-cba           38292
safetynetp            40000  SafetyNET p
crestron-cip          41794  Crestron Control Port
crestron-ctp          41795  Crestron Terminal Port
caerpc                42510  CA eTrust RPC
reachout              43188
tinyfw                44334  tiny personal firewall admin port
coldfusion-auth       44442  Advanced Security/Siteminder Authentication Port
coldfusion-auth       44443  Advanced Security/Siteminder Authentication Port
dbbrowse              47557  Databeam Corporation
directplaysrvr        47624  Direct Play Server
ap                    47806  ALC Protocol
iqobject              48619
compaqdiag            49400  Compaq Web-based management
ibm-db2               50000  (also Internet Input Method Server Framework?)
iiimsf                50002  Internet/Intranet Input Method Server Framework
bo2k                  54320  Back Orifice 2K Default Port
iphone-sync           62078  Apparently used by iPhone while syncing
pcanywhere            65301

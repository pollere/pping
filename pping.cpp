/**********************************************************************
 pping - Pollere Basic Passive Ping

 Copyright (C) 2017  Kathleen Nichols, Pollere, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


 Usage:
    pping -i interfacename
 or
    pping -r pcapfilename

 Typing pping without arguments gives a list of available optional arguments.

 Computes the round trip delay captured packets experience between
 the packet capture point to a host and prints this information to
 standard output, per flow.

 pping is provided as sample code for a basic passive
 ping. It is NOT intended as production code.

 pping operates on TCP headers, v4 or v6. It requires the
 following:
 - time of packet capture
 - packet IP source, destination, sport, and dport
 - TSval and ERC from packet TCP timestamp option
 - both directions of a connection

 The core mechanism saves the first time a TSval is seen and matches it
 with the first time that value is seen as a ERC in the reverse direction.
 Every match produces a round trip time line printed on
 standard output with the format:
    packet capture time (time this round trip delay was observed)
    round trip delay
    shortest round trip delay seen so far for this flow
    flow in the form:  srcIP:port+dstIP:port

 For continued live use, output may be redirected to a file or
 piped to some sort of display or summarization widget.

 More information on pping is available at pollere.net/pping

  ***********************************************************************/

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <ctime>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <cmath>
#include "tins/tins.h"
#include <signal.h>

using namespace Tins;

class flowRec
{
  public:
    explicit flowRec(std::string nm)
    {
        flowname = std::move(nm);
    };
    ~flowRec() = default;

    std::string flowname;
    double last_tm{};
    double min{1e30};   // current min value for capturepoint-to-source RTT
    double bytesSnt{};  // number of bytes sent through CP toward dst
                        // inbound-to-CP, or return, direction
    double lstBytesSnt{};   //value of bytesSnt for flow at previous pping printing
    double bytesDep{};  // set on RTT sample computation for the stream for which
                        // this flow is the "forward" or outbound-from-mp direction.
                        // It is the value of this bytes_snt when a TSval entry was made
                        // and is set when an RTT is computed for this stream by getting a
                        // match on TSval entry by reverse flow, i.e. the number of bytes
                        // departed through CP the last time an RTT was computed for this stream
    bool revFlow{};             //inidcates if a reverse flow has been seen
};

class tsInfo
{
  public:
    explicit tsInfo(double tm, double f, double d)
        : t{tm}, fBytes{f}, dBytes{d} {};
    ~tsInfo() {};
    double t;       //wall clock time of new TSval pkt arrival
    double fBytes;  //total bytes of flow through CP including this pkt
    double dBytes;  //total bytes of in
};

static std::unordered_map<std::string, flowRec*> flows;
static std::unordered_map<std::string, tsInfo*> tsTbl;

#define SNAP_LEN 144                // maximum bytes per packet to capture
static double tsvalMaxAge = 10.;    // limit age of TSvals to use
static double flowMaxIdle = 300.;   // flow idle time until flow forgotten
static double sumInt = 10.;         // how often (sec) to print summary line
static int maxFlows = 10000;
static int flowCnt;
static double time_to_run;      // how many seconds to capture (0=no limit)
static int maxPackets;          // max packets to capture (0=no limit)
static int64_t offTm = -1;      // first packet capture time (used to
                                // avoid precision loss when 52 bit timestamp
                                // normalized into FP double 47 bit mantissa)
static bool machineReadable = false; // machine or human readable output
static double capTm, startm;        // (in seconds)
static int pktCnt, not_tcp, no_TS, not_v4or6, uniDir;
static std::string localIP;         // ignore pp through this address
static bool filtLocal = true;
static std::string filter("tcp");    // default bpf filter
static int64_t flushInt = 1 << 20;  // stdout flush interval (~uS)
static int64_t nextFlush;       // next stdout flush time (~uS)

static bool gINTERRUPTED = false; // Has program caught any OS signals

// save capture time of packet using its flow + TSval as key.  If key
// exists, don't change it.  The same TSval may appear on multiple
// packets so this retains the first (oldest) appearance which may
// overestimate RTT but won't underestimate. This slight bias may be
// reduced by adding additional fields to the key (such as packet's
// ending tcp_seq to match against returned tcp_ack) but this can
// substantially increase the state burden for a small improvement.

static inline void addTS(const std::string& key, tsInfo* ti)
{
    bool empSuccess = false;
#ifdef __cpp_lib_unordered_map_try_emplace
    empSuccess = tsTbl.try_emplace(key, ti).second;
#else
    if (tsTbl.count(key) == 0) {
        empSuccess = tsTbl.emplace(key, ti).second;
    }
#endif

    // Check if emplace succeeded; delete object if it did not
    if (!empSuccess)
        delete ti;
}

// A packet's ECR (timestamp echo reply) should match the TSval of some
// packet seen earlier in the flow's reverse direction so lookup the
// capture time recorded above using the reversed flow + ECR as key. If
// found, the difference between now and capture time of that packet is
// >= the current RTT. Multiple packets may have the same ECR but the
// first packet's capture time gives the best RTT estimate so the time
// in the entry is negated after retrieval to prevent reuse.  The entry
// can't be deleted yet because TSvals may change on time scales longer
// than the RTT so a deleted entry could be recreated by a later packet
// with the same TSval which could match an ECR from an earlier
// incarnation resulting in a large RTT underestimate.  Table entries
// are deleted after a time interval (tsvalMaxAge) that should be:
//  a) longer than the largest time between TSval ticks
//  b) longer than longest queue wait packets are expected to experience

static inline tsInfo* getTStm(const std::string& key)
{
    try {
        tsInfo* ti = tsTbl.at(key);
        return ti;
    } catch (std::out_of_range) {
        return nullptr;
    }
}

static std::string fmtTimeDiff(double dt)
{
    const char* SIprefix = "";
    if (dt < 1e-3) {
        dt *= 1e6;
        SIprefix = "u";
    } else if (dt < 1) {
        dt *= 1e3;
        SIprefix = "m";
    }
    const char* fmt;
    if (dt < 10.) {
        fmt = "%.2lf%ss";
    } else if (dt < 100.) {
        fmt = "%.1lf%ss";
    } else {
        fmt = " %.0lf%ss";
    }
    char buf[10];
    snprintf(buf, sizeof(buf), fmt, dt, SIprefix);
    return buf;
}

/*
 * return (approximate) time in a 64bit fixed point integer with the
 * binary point at bit 20. High accuracy isn't needed (this time is
 * only used to control output flushing) so time is stretched ~5%
 * ((1024^2)/1e6) to avoid a 64 bit multiply.
 */
static int64_t clock_now(void) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t(tv.tv_sec) << 20) | tv.tv_usec;
}

static void process_packet(const Packet& pkt)
{
    u_int32_t rcv_tsval, rcv_tsecr;
    std::string srcstr, dststr, ipsstr, ipdstr;

    pktCnt++;
    // all packets should be TCP since that's in config
    const TCP* t_tcp;
    if ((t_tcp = pkt.pdu()->find_pdu<TCP>()) == nullptr) {
        not_tcp++;
        return;
    }
    try {
        std::pair<uint32_t, uint32_t> tts = t_tcp->timestamp();
        rcv_tsval = tts.first;
        rcv_tsecr = tts.second;
    } catch (std::exception&) {
        no_TS++;
        return;
    }
    if (rcv_tsval == 0 || (rcv_tsecr == 0 && (t_tcp->flags() != TCP::SYN))) {
        return;
    }

    const IP* ip;
    const IPv6* ipv6;
    if ((ip = pkt.pdu()->find_pdu<IP>()) != nullptr) {
        ipsstr = ip->src_addr().to_string();
        ipdstr = ip->dst_addr().to_string();
    } else if ((ipv6 = pkt.pdu()->find_pdu<IPv6>()) != nullptr) {
        ipsstr = ipv6->src_addr().to_string();
        ipdstr = ipv6->dst_addr().to_string();
    } else {
        not_v4or6++;
        return;
    }
    // Reach here with a TCP packet with timestamp option
    srcstr = ipsstr + ":" + std::to_string(t_tcp->sport());
    dststr = ipdstr + ":" + std::to_string(t_tcp->dport());
    // process capture clock time
    std::time_t result = pkt.timestamp().seconds();
    if (offTm < 0) {
        offTm = static_cast<int64_t>(pkt.timestamp().seconds());
        // fractional part of first usable packet time
        startm = double(pkt.timestamp().microseconds()) * 1e-6;
        capTm = startm;
        if (sumInt) {
            std::cerr << "First packet at "
                      << std::asctime(std::localtime(&result)) << "\n";
        }
    } else {
        // offset capture time
        int64_t tt = static_cast<int64_t>(pkt.timestamp().seconds()) - offTm;
        capTm = double(tt) + double(pkt.timestamp().microseconds()) * 1e-6;
    }

    std::string fstr = srcstr + "+" + dststr;  // could add DSCP field to key
    // Creates a flowRec entry whenever needed
    flowRec* fr;
    if (flows.count(fstr) == 0u) {
        if (flowCnt > maxFlows) {
            // stop adding flows till something goes away
            return;
        }
        fr = new flowRec(fstr);
        flowCnt++;
        flows.emplace(fstr, fr);

        // only want to record tsvals when capturing both directions
        // of a flow. if this flow is the reverse of a known flow,
        // mark both as bi-directional.
        if (flows.count(dststr + "+" + srcstr) != 0u) {
            flows.at(dststr + "+" + srcstr)->revFlow = true;
            fr->revFlow = true;
        }
    } else {
        fr = flows.at(fstr);
    }
    fr->last_tm = capTm;

    if (! fr->revFlow) {
        uniDir++;
        return;
    }

    double arr_fwd = fr->bytesSnt + pkt.pdu()->size();
    fr->bytesSnt = arr_fwd;
    if (!filtLocal || (localIP != ipdstr)) {
        addTS(fstr + "+" + std::to_string(rcv_tsval),
              new tsInfo(capTm, arr_fwd, fr->bytesDep));
    }
    tsInfo* ti = getTStm(dststr + "+" + srcstr + "+" +
                         std::to_string(rcv_tsecr));
    if (ti && ti->t > 0.0) {
	// this packet is the return "pping" --
        // process it for packet's src
        double t = ti->t;
        double rtt = capTm - t;
        if (fr->min > rtt) {
            fr->min = rtt;       //track minimum
        }
        double fBytes = ti->fBytes;
        double dBytes = ti->dBytes;
        double pBytes = arr_fwd - fr->lstBytesSnt;
        fr->lstBytesSnt = arr_fwd;
        flows.at(dststr + "+" + srcstr)->bytesDep = fBytes;

        if (machineReadable) {
            printf("%" PRId64 ".%06d %.6f %.6f %.0f %.0f %.0f",
                    int64_t(capTm + offTm), int((capTm - floor(capTm)) * 1e6),
                    rtt, fr->min, fBytes, dBytes, pBytes);
        } else {
            char tbuff[80];
            struct tm* ptm = std::localtime(&result);
            strftime(tbuff, 80, "%T", ptm);
#ifdef notyet
            printf("%s %s %s %d", tbuff, fmtTimeDiff(rtt).c_str(),
                   fmtTimeDiff(fr->min).c_str(), (int)(fBytes - dBytes));
#else
            printf("%s %s %s", tbuff, fmtTimeDiff(rtt).c_str(),
                   fmtTimeDiff(fr->min).c_str());
#endif
        }
        printf(" %s\n", fstr.c_str());
        int64_t now = clock_now();
        if (now - nextFlush >= 0) {
            nextFlush = now + flushInt;
            fflush(stdout);
        }
        ti->t = -t;     //leaves an entry in the TS table to avoid saving this
                        // TSval again, mark it negative to indicate it's been used
    }
}

static void cleanUp(double n)
{
    // erase entry if its TSval was seen more than tsvalMaxAge
    // seconds in the past.
    for (auto it = tsTbl.begin(); it != tsTbl.end();) {
        if (n - std::abs(it->second->t) > tsvalMaxAge) {
            delete it->second;
            it = tsTbl.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = flows.begin(); it != flows.end();) {
        flowRec* fr = it->second;
        if (n - fr->last_tm > flowMaxIdle) {
            delete it->second;
            it = flows.erase(it);
            flowCnt--;
            continue;
        }
        ++it;
    }
}

// return the local ip address of 'ifname'
// XXX since an interface can have multiple addresses, both IP4 and IP6,
// this should really create a set of all of them and later test for
// membership. But for now we just take the first IP4 address.
static std::string localAddrOf(const std::string ifname)
{
    std::string local{};
    struct ifaddrs* ifap;

    if (getifaddrs(&ifap) == 0) {
        for (auto ifp = ifap; ifp; ifp = ifp->ifa_next) {
            if (ifname == ifp->ifa_name &&
                  ifp->ifa_addr->sa_family == AF_INET) {
                uint32_t ip = ((struct sockaddr_in*)
                               ifp->ifa_addr)->sin_addr.s_addr;
                local = IPv4Address(ip).to_string();
                break;
            }
        }
        freeifaddrs(ifap);
    }
    return local;
}

static inline std::string printnz(int v, const char *s) {
    return (v > 0? std::to_string(v) + s : "");
}

static void printSummary()
{
    std::cerr << flowCnt << " flows, "
              << pktCnt << " packets, " +
                 printnz(no_TS, " no TS opt, ") +
                 printnz(uniDir, " uni-directional, ") +
                 printnz(not_tcp, " not TCP, ") +
                 printnz(not_v4or6, " not v4 or v6, ") +
                 "\n";
}

static struct option opts[] = {
    { "interface", required_argument, nullptr, 'i' },
    { "read",      required_argument, nullptr, 'r' },
    { "filter",    required_argument, nullptr, 'f' },
    { "count",     required_argument, nullptr, 'c' },
    { "seconds",   required_argument, nullptr, 's' },
    { "quiet",     no_argument,       nullptr, 'q' },
    { "verbose",   no_argument,       nullptr, 'v' },
    { "showLocal", no_argument,       nullptr, 'l' },
    { "machine",   no_argument,       nullptr, 'm' },
    { "sumInt",    required_argument, nullptr, 'S' },
    { "tsvalMaxAge", required_argument, nullptr, 'M' },
    { "flowMaxIdle", required_argument, nullptr, 'F' },
    { "help",      no_argument,       nullptr, 'h' },
    { 0, 0, 0, 0 }
};

static void usage(const char* pname) {
    std::cerr << "usage: " << pname << " [flags] -i interface | -r pcapFile\n";
}

static void help(const char* pname) {
    usage(pname);
    std::cerr << " flags:\n"
"  -i|--interface ifname   do live capture from interface <ifname>\n"
"\n"
"  -r|--read pcap     process capture file <pcap>\n"
"\n"
"  -f|--filter expr   pcap filter applied to packets.\n"
"                     Eg., \"-f 'net 74.125.0.0/16 or 45.57.0.0/17'\"\n"
"                     only shows traffic to/from youtube or netflix.\n"
"\n"
"  -m|--machine       'machine readable' output format suitable\n"
"                     for graphing or post-processing. Timestamps\n"
"                     are printed as seconds since capture start.\n"
"                     RTT and minRTT are printed as seconds. All\n"
"                     times have a resolution of 1us (6 digits after\n"
"                     decimal point).\n"
"\n"
"  -c|--count num     stop after capturing <num> packets\n"
"\n"
"  -s|--seconds num   stop after capturing for <num> seconds \n"
"\n"
"  -q|--quiet         don't print summary reports to stderr\n"
"\n"
"  -v|--verbose       print summary reports to stderr every sumInt (10) seconds\n"
"\n"
"  -l|--showLocal     show RTTs through local host applications\n"
"\n"
"  --sumInt num       summary report print interval (default 10s)\n"
"\n"
"  --tsvalMaxAge num  max age of an unmatched tsval (default 10s)\n"
"\n"
"  --flowMaxIdle num  flows idle longer than <num> are deleted (default 300s)\n"
"\n"
"  -h|--help          print help then exit\n"
;
}

static void signalHandler(int sigVal) {
    gINTERRUPTED = true;
}

int main(int argc, char* const* argv)
{
    // Set up signal catching
    struct sigaction action;
    action.sa_handler = signalHandler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction (SIGINT, &action, NULL);
    sigaction (SIGTERM, &action, NULL);

    bool liveInp = false;
    std::string fname;
    if (argc <= 1) {
        help(argv[0]);
        exit(1);
    }
    for (int c; (c = getopt_long(argc, argv, "i:r:f:c:s:hlmqv",
                                 opts, nullptr)) != -1; ) {
        switch (c) {
        case 'i': liveInp = true; fname = optarg; break;
        case 'r': fname = optarg; break;
        case 'f': filter += " and (" + std::string(optarg) + ")"; break;
        case 'c': maxPackets = atof(optarg); break;
        case 's': time_to_run = atof(optarg); break;
        case 'q': sumInt = 0.; break;
        case 'v': break; // summary on by default
        case 'l': filtLocal = false; break;
        case 'm': machineReadable = true; break;
        case 'S': sumInt = atof(optarg); break;
        case 'M': tsvalMaxAge = atof(optarg); break;
        case 'F': flowMaxIdle = atof(optarg); break;
        case 'h': help(argv[0]); exit(0);
        }
    }
    if (optind < argc || fname.empty()) {
        usage(argv[0]);
        exit(1);
    }

    BaseSniffer* snif = nullptr;
    {
        SnifferConfiguration config;
        config.set_filter(filter);
        config.set_promisc_mode(false);
        config.set_snap_len(SNAP_LEN);
        config.set_timeout(250);

        try {
            if (liveInp) {
                snif = new Sniffer(fname, config);
                if (filtLocal) {
                    localIP = localAddrOf(fname);
                    if (localIP.empty()) {
                        // couldn't get local ip addr
                        filtLocal = false;
                    }
                }
            } else {
                snif = new FileSniffer(fname, config);
            }
        } catch (std::exception& ex) {
            std::cerr << "Couldn't open " << fname << ": " << ex.what() << "\n";
            if (snif != nullptr) {
                delete snif;
            }

            exit(EXIT_FAILURE);
        }
    }
    if (liveInp && machineReadable) {
        // output every 100ms when piping to analysis/display program
        flushInt /= 10;
    }
    nextFlush = clock_now() + flushInt;

    double nxtSum = 0., nxtClean = 0.;

    for (const auto& packet : *snif) {
        process_packet(packet);

        if ((time_to_run > 0. && capTm - startm >= time_to_run) ||
            (maxPackets > 0 && pktCnt >= maxPackets)) {
            printSummary();
            std::cerr << "Captured " << pktCnt << " packets in "
                      << (capTm - startm) << " seconds\n";
            break;
        }
        if (capTm >= nxtSum && sumInt) {
            if (nxtSum > 0.) {
                printSummary();
                pktCnt = 0;
                no_TS = 0;
                uniDir = 0;
                not_tcp = 0;
                not_v4or6 = 0;
            }
            nxtSum = capTm + sumInt;

        }
        if (capTm >= nxtClean) {
            cleanUp(capTm);  // get rid of stale entries
            nxtClean = capTm + tsvalMaxAge;
        }

        if (gINTERRUPTED)
            break;
    }

    // Force clean-up of all data structures by adding to capTm
    cleanUp(capTm + (tsvalMaxAge > flowMaxIdle ? tsvalMaxAge : flowMaxIdle) + 1);

    exit(0);
}


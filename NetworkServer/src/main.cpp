#include "NetworkServer.hpp"
#include <iostream>
#include <csignal>

static NetworkServer *g_ns = nullptr;
void sighandler(int) { if (g_ns) g_ns->stop(); exit(0); }

int main() {
    signal(SIGINT, sighandler);
    NetworkServer ns;
    g_ns = &ns;
    ns.start();
    while(true) pause();
    return 0;
}

package Goose;

import Parser.PacketParser;
import lombok.SneakyThrows;
import org.pcap4j.core.*;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Class represents API for gse messages parsing. it allows detecting gse values of income data
 */
public class GooseAdapter {
    private List<ChangesListener> listeners = new ArrayList<>();
    private Dataset prev;

    @SneakyThrows
    public void start(GoosePdu goosePduXML){
        //TODO: transfer buisness logic from main

        InetAddress addr = InetAddress.getByName(goosePduXML.getDataset().getIfaceIp());
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 1000;
        PcapHandle handle = nif.openLive(snapLen, mode, timeout);

        handle.setFilter("ether proto 0x88B8", BpfProgram.BpfCompileMode.NONOPTIMIZE);

        handle.loop(0, (PacketListener) packet -> {
            GoosePdu goosePduParse = PacketParser.parse(packet, goosePduXML);

            if (goosePduParse.getDataset() != null) {
                if (goosePduParse.getDataset().isDataChanged(prev, goosePduParse.getDataset())) {
                    prev = goosePduParse.getDataset();
                    listeners.forEach(el -> el.changed(goosePduParse.getDataset()));
                }
            }
        });
    }

    public void addListener(ChangesListener listener){
        listeners.add(listener);
    }
}

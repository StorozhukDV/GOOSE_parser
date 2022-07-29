import Goose.*;

import Goose.ChangesListener;
import Parser.XMLparser;
import org.pcap4j.core.*;
import org.w3c.dom.*;
import java.io.EOFException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.TimeoutException;


public class main {
    public static void main(String[] args) throws UnknownHostException,

            PcapNativeException,
            NotOpenException,
            EOFException,
            TimeoutException,
            InterruptedException {
        GooseAdapter ga = new GooseAdapter();
        GoosePdu goosePduXML = new GoosePdu();
        Document doc;
        try {
            doc = XMLparser.buildDocument();
        } catch (Exception e) {
            System.out.println("Open parsing error " + e.toString());
            return;
        }

        Node rootNode = doc.getFirstChild();
        NodeList nodelist = rootNode.getChildNodes();
        for (int i = 0; i<nodelist.getLength(); i++){
            if (nodelist.item(i).getNodeType() != Node.ELEMENT_NODE){
                continue;
            }
            NamedNodeMap atribut =  nodelist.item(i).getAttributes();
            if (nodelist.item(i).getNodeName().equals("dataset")){
                Dataset dataset = XMLparser.datasetBuilder(atribut);
                NodeList datalist = nodelist.item(i).getChildNodes();
                List<Goose.Data> dataL = XMLparser.dataBuilder(datalist);
                dataset.setData(dataL);
                goosePduXML.setDataset(dataset);
                System.out.println(goosePduXML);
            }
        }

        ga.addListener(new ChangesListener() {
            @Override
            public void changed(Dataset pdu) {
                System.out.println(pdu);
            }
        });
        ga.start(goosePduXML);


    }
}



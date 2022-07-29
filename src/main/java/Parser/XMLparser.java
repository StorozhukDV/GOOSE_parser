package Parser;

import Goose.Dataset;
import lombok.Data;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Data
public class XMLparser {

    public static Document buildDocument() throws Exception{
        File file = new File("goosePdu.xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(file);
    }

    public static Dataset datasetBuilder(NamedNodeMap atribut){
        Dataset dataset = new Dataset();
        dataset.setSource(atribut.getNamedItem("Source").getNodeValue());
        dataset.setDestination(atribut.getNamedItem("Destination").getNodeValue());
        dataset.setTime(Boolean.parseBoolean(atribut.getNamedItem("time").getNodeValue()));
        dataset.setQuality(Boolean.parseBoolean(atribut.getNamedItem("quality").getNodeValue()));
        dataset.setIfaceIp(atribut.getNamedItem("IfaceIp").getNodeValue());
        dataset.setTimeType(atribut.getNamedItem("TimeType").getNodeValue());

        return dataset;
    }

    public static List<Goose.Data> dataBuilder(NodeList datalist) {

        List<Goose.Data> dataL = new ArrayList<>();
        for (int j = 0; j < datalist.getLength(); j++) {
            if (datalist.item(j).getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            NamedNodeMap atribut = datalist.item(j).getAttributes();
            if (datalist.item(j).getNodeName().equals("Data")) {
                Goose.Data data = new Goose.Data();
                data.setType(atribut.item(0).getNodeValue());
                dataL.add(data);
            }
        }
        return dataL;
    }
}

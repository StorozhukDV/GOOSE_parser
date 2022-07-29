package Parser;

import Goose.Dataset;
import Goose.GoosePdu;
import model.Destination;
import model.GseDataItem;
import model.Source;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.List;

//Парсер сырой даты
public class PacketParser {


    public static GoosePdu parse(Packet packet, GoosePdu goosePduXML) {
        GoosePdu gse = new GoosePdu();
        Dataset datasetParse = new Dataset();
        Tags tags = new Tags();

        byte[] etherheader = packet.getRawData();

        Destination destination = new Destination();
        Source source = new Source();

        String eatherhead = ByteArrays.toHexString(etherheader, ":");

        destination.setDestination(eatherhead.substring(0,17));
        source.setSource(eatherhead.substring(18,35));

        if (destination.getDestination().equals(goosePduXML.getDataset().getDestination())
        && source.getSource().equals(goosePduXML.getDataset().getSource())){

            datasetParse.setSource(source.getSource());
            datasetParse.setDestination(destination.getDestination());
            int[] bytes = unsignedBytes(etherheader);
            int len = Hex_to_INT(bytes,16,17);

            int[] smallerData = new int[len];

            System.arraycopy(bytes, 25, smallerData, 0, len-11);
            int[] bytesNew = smallerData;



            int lenGocbRef = length(bytesNew, tags.getGOCB_REF_TAG());
            String gocbRef = Hex_to_ASCII_Tags(tags.getGOCB_REF_TAG(),lenGocbRef, bytesNew);
            bytesNew = arrayCopy(bytesNew,lenGocbRef);

            int lenTimeAllowedToLive = length(bytesNew, tags.getTIME_ALLOWED_TO_LIVE_TAG());
            bytesNew = arrayCopy(bytesNew,lenTimeAllowedToLive);

            int lenDatSet = length(bytesNew, tags.getDAT_SET_TAG());
            bytesNew = arrayCopy(bytesNew,lenDatSet);

            int lenGoId = length(bytesNew, tags.getGO_ID_TAG());
            String goID = Hex_to_ASCII_Tags(tags.getGO_ID_TAG(),lenGoId, bytesNew);
            bytesNew = arrayCopy(bytesNew,lenGoId);

            int lenTime = length(bytesNew, tags.getTIME_TAG());
            bytesNew = arrayCopy(bytesNew,lenTime);

            int lenStNum = length(bytesNew, tags.getST_NUM_TAG());
            int stNum = Hex_to_INT_Tags(tags.getST_NUM_TAG(),lenStNum, bytesNew);
            bytesNew = arrayCopy(bytesNew,lenStNum);

            int lenSqNum = length(bytesNew, tags.getSQ_NUM_TAG());
            int sqNum = Hex_to_INT_Tags(tags.getSQ_NUM_TAG(),lenSqNum, bytesNew);
            bytesNew = arrayCopy(bytesNew,lenSqNum);

            bytesNew = arrayCopy(bytesNew,7);

            int lenNumDatSetEntries = length(bytesNew, tags.getNUM_DAT_SET_ENTRIES_TAG());
            int numDatSetEntries = Hex_to_INT_Tags(tags.getNUM_DAT_SET_ENTRIES_TAG(),lenNumDatSetEntries, bytesNew);
            bytesNew = arrayCopy(bytesNew,lenNumDatSetEntries+1);

            List<GseDataItem> gseDataItems = parseAllData(bytesNew
                    ,numDatSetEntries
                    ,goosePduXML
                    ,tags);

            datasetParse.setTime(goosePduXML.getDataset().isTime());
            datasetParse.setQuality(goosePduXML.getDataset().isQuality());

            datasetParse.setGseData(gseDataItems);
            datasetParse.setGocbRef(gocbRef);
            datasetParse.setGoID(goID);
            datasetParse.setStNum(stNum);
            datasetParse.setSqNum(sqNum);
            datasetParse.setNumDatSetEntries(numDatSetEntries);
            datasetParse.setTimeType(goosePduXML.getDataset().getTimeType());
            datasetParse.setIfaceIp(goosePduXML.getDataset().getIfaceIp());
            gse.setDataset(datasetParse);
        }
        return gse;
    }



    private static int[] arrayCopy(int[] bytes, int len){
        int length = bytes.length - (len+2);
        int[] smallerData = new int[length];
        System.arraycopy(bytes, len+2, smallerData, 0, length);
        bytes = smallerData;

        return bytes;
    }



    private static int[] unsignedBytes(byte[] etherheader){
        int[] bytes = new int[etherheader.length];
        for (int j = 0; j < etherheader.length; j++) {
            bytes[j] = etherheader[j] & 0xFF; //bytes to unsigned bytes to be able to read tags
        }
        return bytes;
    }

    private static int length(int[] arr, int tag_Start){
        //method to define length of a goose-message attribute
        int a;

        for (a=0; a <arr.length ; a++) {
            if (arr[a]==tag_Start) break;
        }
        return arr[a+1];
    }

    private static String Hex_to_ASCII_Tags( int tag_Start, int len, int[] arr){
        StringBuilder hexString= new StringBuilder();
        StringBuilder output = new StringBuilder("");

        if (arr[0]==tag_Start){
            for(int j=0;j<len;j++){
                hexString.append(Integer.toHexString(arr[j+2]));
            }
        }

        for (int j = 0; j < hexString.length(); j += 2) {
            String str = hexString.substring(j, j + 2);

            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    private static int[] Hex_to_ASCII_Tags(int[] arr, int tag, int len) {
        //method returns attribute's data
        int[] temp = new int[len];
        int j;
        for (j=0;  j < arr.length; j++) {
            if (arr[j] == tag) {
                for (int t = 0; t < temp.length; t++) {
                    temp[t] = arr[j + 2];
                    j++;
                }
                break;
            }
        }
        return temp;
    }

    private static String Hex_to_ASCII_Tags_QUALITY( int tag_Start, int len, int[] arr){
        StringBuilder hexString= new StringBuilder();
        StringBuilder output = new StringBuilder("");

        if (arr[0]==tag_Start){
            for(int j=0;j<len;j++){
                hexString.append(Integer.toHexString(arr[j+2]));
            }
        }

        for (int j = 1; j < hexString.length(); j += 2) {
            String str = hexString.substring(j, j + 2);

            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }


    private static int Hex_to_INT_Tags( int tag_Start, int len, int[] arr){
        StringBuilder hexString = new StringBuilder();
        if (arr[0]==tag_Start){
            for(int j=0;j<len;j++){
                hexString.append(Integer.toHexString(arr[j+2]));
            }
        }
        return Integer.parseInt(String.valueOf(hexString),16);
    }


    private static String Hex_to_ASCII(int[] arr, int tag_Start, int tag_End){
        StringBuilder hexString= new StringBuilder();
        StringBuilder output = new StringBuilder("");


        for (int i = tag_Start; i <= tag_End; i++){
            hexString.append(Integer.toHexString(arr[i]));
        }

        for (int j = 0; j < hexString.length(); j += 2) {
            String str = hexString.substring(j, j + 2);

            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    private static int Hex_to_INT(int[] arr, int index, int count){
        StringBuilder hexString= new StringBuilder();
        for (int i = index; i <count+1 ; i++) {
            hexString.append(Integer.toHexString(arr[i]));
        }
        return Integer.parseInt(String.valueOf(hexString),16);
    }

    private static long Hex_to_LONG(int[] temp){
        StringBuilder hexString= new StringBuilder();
        for (int j : temp) {
            hexString.append(Integer.toHexString(j));
        }
        return Long.parseLong(String.valueOf(hexString),16);
    }

    private static String Hex_to_String_QUALITY(int[] temp){
        StringBuilder hexString= new StringBuilder();
        for (int j = 1; j < temp.length; j++) {
            hexString.append(Integer.toHexString(temp[j]));
        }
        return String.valueOf(hexString);
    }


    private static boolean Hex_to_bool(int[] arr){
        boolean bool;
        bool= arr[0] != 0;
        return bool;
    }

    private static int[] Hex_to_ASCII_Tags_Float(int[] arr, int tag, int len) {
        //method returns attribute's data
        int[] temp = new int[len];
        int j;
        for (j=0;  j < arr.length; j++) {
            if (arr[j] == tag) {
                for (int t = 0; t < temp.length; t++) {
                    temp[t] = arr[j + 3];
                    j++;
                }
                break;
            }
        }
        return temp;
    }
    private static float Hex_to_FLOAT(int[] temp){
        int i = temp[3] & 0xFF |
                (temp[2] & 0xFF) << 8 |
                (temp[1] & 0xFF) << 16 |
                (temp[0] & 0xFF) << 24;
        return Float.intBitsToFloat(i);
    }

    private static List<GseDataItem> parseAllData(int[] bytesData, int numDatSetEntries, GoosePdu goosePduXML, Tags tags) {
        List<GseDataItem> outData = new ArrayList<>();
        if (goosePduXML.getDataset().isQuality() && goosePduXML.getDataset().isTime()) {
            int size = numDatSetEntries / 3;
            for (int i = 0; i < size; i++) {
                GseDataItem gseDat = new GseDataItem();
                int tag = 0;
                int lenValue;
                int[] value;
                Object val;
                switch (goosePduXML.getDataset().getData().get(i).getType()) {
                    case "boolean":
                        tag = tags.getBOOLEAN_DATA_TAG();
                        lenValue = length(bytesData, tag);
                        value = Hex_to_ASCII_Tags(bytesData, tag, lenValue);
                        bytesData = arrayCopy(bytesData, lenValue);
                        val = Hex_to_bool(value);
                        gseDat.setValue(val);
                        break;
                    case "integer":
                        tag = tags.getINTEGER_DATA_TAG();
                        lenValue = length(bytesData, tag);
                        value = Hex_to_ASCII_Tags(bytesData, tag, lenValue);
                        bytesData = arrayCopy(bytesData, lenValue);
                        val = Hex_to_LONG(value);
                        gseDat.setValue(val);
                        break;
                    case "float":
                        tag = tags.getFLOAT_DATA_TAG();
                        lenValue = length(bytesData, tag);
                        value = Hex_to_ASCII_Tags_Float(bytesData, tag, lenValue);
                        bytesData = arrayCopy(bytesData, lenValue);
                        val = Hex_to_FLOAT(value);
                        gseDat.setValue(val);
                        break;
                    default:
                        System.out.println("Not supported type of Value" + goosePduXML.getDataset().getData().get(i).getType());
                        break;
                }

                int lenQuality = length(bytesData, tags.getQUALITY_DATA_TAG());
                int[] temp = Hex_to_ASCII_Tags(bytesData, tags.getQUALITY_DATA_TAG(), lenQuality);
                String quality = Hex_to_String_QUALITY(temp);
                bytesData = arrayCopy(bytesData,lenQuality);
                gseDat.setQuality(quality);


                tag = 0x85;
                if (goosePduXML.getDataset().getTimeType().equals("utc")) {
                    tag = 0x91;
                }

                int lenTimeData = length(bytesData, tag);
                int[] timetemp = Hex_to_ASCII_Tags(bytesData, tag, lenTimeData);
                long time = Hex_to_LONG(timetemp);
                bytesData = arrayCopy(bytesData,lenTimeData);
                gseDat.setTime(time);
                outData.add(gseDat);
            }
        } else {
            for (int i = 0; i < numDatSetEntries; i++) {
                GseDataItem gseDat = new GseDataItem();
                int tag = 0;
                int lenValue;
                int[] value;
                Object val;
                switch (goosePduXML.getDataset().getData().get(i).getType()) {
                    case "boolean":
                        tag = tags.getBOOLEAN_DATA_TAG();
                        lenValue = length(bytesData, tag);
                        value = Hex_to_ASCII_Tags(bytesData, tag, lenValue);
                        bytesData = arrayCopy(bytesData, lenValue);
                        val = Hex_to_bool(value);
                        gseDat.setValue(val);
                        break;
                    case "integer":
                        tag = tags.getINTEGER_DATA_TAG();
                        lenValue = length(bytesData, tag);
                        value = Hex_to_ASCII_Tags(bytesData, tag, lenValue);
                        bytesData = arrayCopy(bytesData, lenValue);
                        val = Hex_to_LONG(value);
                        gseDat.setValue(val);
                        break;
                    case "float":
                        tag = tags.getFLOAT_DATA_TAG();
                        lenValue = length(bytesData, tag);
                        value = Hex_to_ASCII_Tags_Float(bytesData, tag, lenValue);
                        bytesData = arrayCopy(bytesData, lenValue);
                        val = Hex_to_FLOAT(value);
                        gseDat.setValue(val);
                        break;
                    default:
                        System.out.println("Not supported type of Value" + goosePduXML.getDataset().getData().get(i).getType());
                        break;
                }
                outData.add(gseDat);
            }
        }
        return outData;
    }
}



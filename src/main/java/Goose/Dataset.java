package Goose;

import lombok.Data;
import model.GseDataItem;

import java.util.List;

@Data
public class Dataset {

    private String source;
    private String Destination;
    private String gocbRef;
    private String goID;
    private int stNum;
    private int sqNum;
    private boolean time;
    private boolean quality;
    private int numDatSetEntries;
    private List<Goose.Data> data;
    private List<GseDataItem> gseData;
    private String IfaceIp;
    private String TimeType;


    public boolean isDataChanged(Dataset oldOne, Dataset newOne){
        if (oldOne==null) return true;
        //TODO: check gseDataItem changes
        if(
        !oldOne.getSource().equals(newOne.getSource())||
        !oldOne.getDestination().equals(newOne.getDestination())||
        !oldOne.getGocbRef().equals(newOne.getGocbRef())||
        !oldOne.getGoID().equals(newOne.getGoID())||
        oldOne.getStNum()!=newOne.getStNum()){
            return true;
        }
        return false;
    }
}

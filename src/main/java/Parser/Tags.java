package Parser;

import lombok.Data;

@Data
public class Tags {
    private int GOCB_REF_TAG = 0x80;
    private int TIME_ALLOWED_TO_LIVE_TAG = 0x81;
    private int DAT_SET_TAG = 0x82;
    private int GO_ID_TAG = 0x83;
    private int TIME_TAG = 0x84;
    private int ST_NUM_TAG = 0x85;
    private int SQ_NUM_TAG = 0x86;
    private int TEST_TAG = 0x87;
    private int NUM_DAT_SET_ENTRIES_TAG = 0x8a;
    private int ALL_DATA_TAG = 0xab;
    private int BOOLEAN_DATA_TAG = 0x83;
    private int QUALITY_DATA_TAG = 0x84;
    private int TIME_DATA_TAG = 0x91;
    private int INTEGER_DATA_TAG = 0x85;
    private int FLOAT_DATA_TAG = 0x87;

}

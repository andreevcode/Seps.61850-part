package ru.smarteps.iec61850;

import java.security.Timestamp;

public class GooseMessage {
	public String gocbRref;
	public Long timeAllowedtoLive;
	public String datSet;
	public String goID;
	public ru.smarteps.iec61850.Timestamp t;
	public int stNum;
	public int sqNum;
	public Boolean test=false;
	public int confRev;
	public Boolean ndsCom=false;
	public int numDatasetEnries=0;
	public Boolean simulation=false;
	
	public GooseValue[] DataSet;
//	public DataSet[] decode(byte[] packet) throws Exception {
//    
//    public boolean compare (Object obj){
//    	GooseValue goose = (GooseValue)obj;
//    	if ((this.quality!=goose.quality)||(this.valtype!=goose.valtype)||(this.t!=goose.t))
//    	{
//    		return false;
//    	}
//    	return true;
//    }
}


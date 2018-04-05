package ru.smarteps.iec61850.tests;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import ru.smarteps.iec61850.BadDataException;
import ru.smarteps.iec61850.EthernetListener;
import ru.smarteps.iec61850.GooseDecoder;
import ru.smarteps.iec61850.GooseMessage;
import ru.smarteps.iec61850.SampleValue;

@Ignore
public class GooseComplexTest {

	public static final int TIME_FOR_CAPTURE=15000; //ms
	private final static String LINUX_CONFIG = "complexTestLinux.properties";
	private final static String WINDOWS_CONFIG = "complexGooseTestWindows.properties";
	
	@Test
	public void GooseComplexTest() {
		EthernetListener el=null;
		String propertyFile="";
		GooseDecoder gd = new GooseDecoder();
		String osName = System.getProperty("os.name");
		if (osName.equals("Linux")) propertyFile = LINUX_CONFIG;
		else propertyFile = WINDOWS_CONFIG;
		Properties properties = new Properties();
		InputStream in=null;
		
		try {
			in = Thread.currentThread()
					.getContextClassLoader().getResourceAsStream(propertyFile);
			properties.load(in);		
			} catch (Exception e1) {
			e1.printStackTrace();
			Assert.fail(e1.getMessage());
		}
		try {
			el = new EthernetListener();
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.getMessage());
		}
		try {
			Thread.sleep(TIME_FOR_CAPTURE); //waiting for packets to be captured
		} catch (InterruptedException e) {
			Assert.fail(e.getMessage());
		}
		el.stop();
		LinkedList<byte[]> result=null;
		try {
			result = el.getPacketQueue();
		} catch (BadDataException e1) {
			e1.printStackTrace();
		}
		Assert.assertTrue("Data not captured", result.size()!=0);
		ArrayList<GooseMessage> gmessages = new ArrayList<GooseMessage>();
		for (byte[] packet : result){
			try {
				GooseMessage gooses = gd.decode(packet);
				gmessages.add(gooses);
			} catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		}
		Assert.assertTrue("No samples received", gmessages.size()>0);
		
//		"t:"+gmessages.get(i).t.toString()+
		for (int i=0; i<gmessages.size(); i++){
			System.out.println("GoID: "+gmessages.get(i).goID + " ,sqNum: " + gmessages.get(i).sqNum + 
					" ,stNum: " + gmessages.get(i).stNum+" ,numDataSetEntries: "
					+gmessages.get(i).numDatasetEnries);
		}
		
	}

}

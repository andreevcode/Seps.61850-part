package ru.smarteps.iec61850.tests;

import java.io.InputStream;
import java.util.LinkedList;
import java.util.Properties;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import ru.smarteps.iec61850.BadDataException;
import ru.smarteps.iec61850.EthernetListener;
import ru.smarteps.iec61850.EthernetListener24;

public class EthernetListener24Test {
	private final static String LINUX_CONFIG = "testEthernetLinux.properties";
	private final static String WINDOWS_CONFIG = "testEthernetWindows.properties";
//    @Rule
//    public Timeout globalTimeout = new Timeout(10000);
	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public final void testEthernetListener() {
		EthernetListener24 el = null;
		String propertyFile="";
		String osName = System.getProperty("os.name");
		if (osName.equals("Linux")) propertyFile = LINUX_CONFIG;
		else propertyFile = WINDOWS_CONFIG;
		Properties properties = new Properties();
		try {
			InputStream in = Thread.currentThread()
					.getContextClassLoader().getResourceAsStream(propertyFile);
			properties.load(in);		
			} catch (Exception e1) {
			e1.printStackTrace();
			Assert.fail(e1.getMessage());
		}
		
		try {
			el = new EthernetListener24();
			el.setIface(properties.getProperty("EthInterface"));
			el.start();
		} catch (Exception e) {
			e.printStackTrace();
			if (e.getMessage().equals("Не найдены сетевые интерфейсы")) return;
			Assert.fail(e.getMessage());
		}
		try {
			Thread.sleep(500);
		} catch (InterruptedException e) {
			e.printStackTrace();
			Assert.fail();
		}
		LinkedList<byte[]> queue=null;
		try {
			queue = el.getPacketQueue();
		} catch (BadDataException e) {
			e.printStackTrace();
		}
		Assert.assertTrue(queue!=null);
		el.stop();
	}

}

/**
 * 
 */
package ru.smarteps.iec61850.tests;

import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import ru.smarteps.iec61850.DataSet;
import ru.smarteps.iec61850.EthernetSender;
import ru.smarteps.iec61850.GooseSender;
import ru.smarteps.iec61850.GooseValueDefinition;
import supportClasses.DummyEthernetSender;

/**
 *
 */
public class GooseSenderTest {
	GooseSender gs;
	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		gs = new GooseSender();
		gs.setConfRev(0);
		DataSet ds = new DataSet();
		for (int i=0; i<16; i++){
			GooseValueDefinition gvd = new GooseValueDefinition();
			gvd.valtype=Boolean.class;
			gvd.val = true;
			ds.add(gvd);
		}
		gs.setDataSet(ds);
		gs.setDataSetName("testname");
		gs.setGocbRef("LNstuff");
		gs.setGoID("1");
		gs.setMacDst("01:0c:cd:01:00:02");
		gs.setMacSource("01:0c:cd:01:00:02");
		DummyEthernetSender es = new DummyEthernetSender();
		es.start();
		gs.setEthernetSender(es);
		gs.setNdsCom(true);
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for {@link ru.smarteps.iec61850.GooseSender#SendGoose()}.
	 */
	@Test
	public void testSendGoose() {
		try {
			gs.start();
			gs.SendGoose();
			Thread.sleep(500);
		} catch ( Exception e) {
			e.printStackTrace();
			Assert.fail();
		}
		
	}

	/**
	 * Test method for {@link ru.smarteps.iec61850.GooseSender#start()}.
	 */
	@Test
	public void testStart() {
		try {
			gs.start();
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail();
		}
		Assert.assertNotNull(gs);
	}

}

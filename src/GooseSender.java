package ru.smarteps.iec61850;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Calendar;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.openmuc.jasn1.ber.BerByteArrayOutputStream;
import org.openmuc.jasn1.ber.BerIdentifier;
import org.openmuc.jasn1.ber.BerLength;
import org.openmuc.jasn1.ber.types.BerBitString;
import org.openmuc.jasn1.ber.types.BerBoolean;
import org.openmuc.jasn1.ber.types.BerInteger;
import org.openmuc.jasn1.ber.types.string.BerVisibleString;
//import org.pcap4j.core.NativeMappings.bpf_insn;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ru.smarteps.iec61850.interfaces.AbstractGooseSender;
//import org.pcap4j.core.NativeMappings.bpf_insn;
//import org.pcap4j.core.NativeMappings.win_pcap_stat;

/**Класс отправляющий GOOSE сообщения
 * @author AndreevAA
 */
public class GooseSender implements AbstractGooseSender{
	
	/**
	 * Последовательность пауз между отправками GOOSE сообщений
	 */
	int[] delays = {0,12,24,48,96,192,384,768,1536};
//	int[] delays = {0,100,200,400,800,1600,3200};
	
	/**
	 * Шаблон GOOSE сообщения
	 */
	private String resourcePath="/Template_GOOSE.raw";
	/**
	 * МАС адрес назначения
	 */
	private String macDst;
	/**
	 * МАС адрес источника
	 */
	private String macSource;
	/**
	 * Имя сетевого интерфейса
	 */
	private String ifname;
	/**
	 * Массив байт данных для отправки 
	 */
	private byte[] rawData=null;
	/**
	 * Массив байт адреса назначения
	 */
	private byte[] macDstByte=null;
	/**
	 * Массив байт адреса источника сообщения
	 */
	private byte[] macSourceByte=null;
	
	
	/**
	 * Кодировщик идентификатора
	 */
	private BerIdentifier bi = new BerIdentifier();
	/**
	 * Кодировщик длин полей
	 */
	private BerLength bLength = new BerLength();
	/**
	 * Кодировщик строк
	 */
	private BerVisibleString berString  = new BerVisibleString();
	/**
	 * Кодировщик целочисленных даннхы
	 */
	private BerInteger berInt = new	BerInteger();
	/**
	 * Кодировщик булевых данных
	 */
	private BerBoolean berBoolean = new BerBoolean();
	/**
	 * Кодировщик наборов бит
	 */
	private BerBitString berBitString = new BerBitString();
	
	/**
	 * Менеджер потоков отправки сообщений
	 */
	private final ScheduledExecutorService gooseScheduler = Executors.newScheduledThreadPool(1);
	/**
	 * Результат выполнения потока
	 */
	ScheduledFuture future;

	/**
	 * Пакет для отправки
	 */
	private EthernetPacket gooseEthernetPacket;
	/**
	 * Приемник журнала событий
	 */
	final Logger logger = LoggerFactory.getLogger(this.getClass());
	/**
	 * Имя узла в конфигурации XML
	 */
	protected String name;
	/**
	 * Отправляемый DataSet
	 */
	protected DataSet dataSet;
	/**
	 * Имя отправляемого DataSet'a
	 */
	protected String dataSetName;
	
	/**
	 * Отправщик сообщений в сетевой интерфейс
	 */
	protected EthernetSender ethernetSender;
	/**
	 * Шаблон GOOSE сообщения
	 */
	protected GooseMessage templateMessage;
	/**
	 * Поле goID
	 */
	protected String goID;
	/**
	 * Поле gocbRef
	 */
	protected String gocbRef;
	/**
	 * Поле ndsCom
	 */
	protected Boolean ndsCom;
	/**
	 * Задание на отправку сообщения
	 */
	protected Runnable sender;
	/**
	 * Поле confRev
	 */
	private int confRev=1;
	
	/**
	 * Текущая задержка отправки сообщения
	 */
	private int delay;
	/**
	 * Поле timeAllowed
	 */
	private int timeAllowed;

	private boolean paused=false;


	/**
	 * Конструктор по умолчанию
	 * 
	 * <pre>
	 * {@code
	 * <gooseSender
	 * 			config-class="ru.smarteps.iec61850.GooseSender"
	 * 			macSource="1c:c1:de:b7:ef:89"
	 * 			macDst="01:0c:cd:01:01:FF"
	 * 			name="gs1"
	 * 			confRev="1"
	 * 			goID="gtnet_1"
	 * 			ndsCom="false"
	 * 			gocbRef="MASCTRL/LLN0$GO$GOOSE_outputs_control"
	 * 			dataSetName="MASCTRL/LLN0$GOOSE_outputs">
	 * </gooseSender>
	 * }
	 * </pre>
	 */
	public GooseSender(){
		//Пустой конструктор в соответствии с требованиями JavaBean
		//Сначала создается пустой объект, потом из файла настроек автоматически
		//подтягиваются значения полей через методы вида setName(String name)
		//потом собственно инициализация в методе start()
	}
	
	//создание шаблона GOOSE сообщения в соответствии с файлом IED_GOOSE.properties
	
	//Prepare GOOSE message in byte[] 
	/**Подготавливает к отправке GOOSE сообщение (в массив байт)
	 * @param gs структурированное сообщение
	 * @throws IOException
	 * @throws IEDException
	 */
	public void PrepareGoose(GooseMessage gs) throws IOException, IEDException{	

		BerByteArrayOutputStream baos = new BerByteArrayOutputStream(1000);
		int length=0;
		if (gs.DataSet==null) throw new IEDException();
		//кодировка элементов DataSet
		for (int i=gs.DataSet.length-1;i>=0;i--){
			if (gs.DataSet[i].valtype==Boolean.class){
				length=0;
				berBoolean = new BerBoolean((Boolean)gs.DataSet[i].val);
				length+=berBoolean.encode(baos, false);
				GooseDecoder.x83.encode(baos);
			}
			else if (gs.DataSet[i].valtype==Integer.class){
					length=0;
					berInt = new BerInteger(((Integer)gs.DataSet[i].val).longValue());
					length+=berInt.encode(baos, false);
					GooseDecoder.x85.encode(baos);
			}
			else if (gs.DataSet[i].valtype==Float.class){
				length=0;
				byte[] floatValue = ByteBuffer.allocate(4).putFloat((float)gs.DataSet[i].val).array();
				baos.write(floatValue);
				baos.write(8);
				baos.write(5);
				GooseDecoder.x87.encode(baos);
			}
			//если есть quality
			if (gs.DataSet[i].quality!=null){
				length=0;
				byte [] quality = toByteArray( gs.DataSet[i].quality);
				if (quality.length==0) {
					baos.write(0);
					baos.write(0);
				}
				else baos.write(quality);
				if (quality.length==1) {baos.write(0);}
				baos.write(3);
				baos.write(3);
				GooseDecoder.x84.encode(baos);
			}	
		}
		
		//кодировка alldata
		bLength = new BerLength();
		bLength.encodeLength(baos, baos.getArray().length);	
		GooseDecoder.alldata.encode(baos);
		
		length=0;//кодировка numDatSetEntries
		berInt = new BerInteger(gs.numDatasetEnries);
		length+=berInt.encode(baos, false);
		GooseDecoder.numDatSetEntries.encode(baos);
		
		length=0;//кодировка ndsCom
		berBoolean = new BerBoolean(gs.ndsCom);
		length+=berBoolean.encode(baos, false);
		GooseDecoder.ndsCom.encode(baos);
		
		length=0;//кодировка confRev
		berInt = new BerInteger(gs.confRev);
		length+=berInt.encode(baos, false);
		GooseDecoder.confRev.encode(baos);
		
		length=0;//кодировка simulation
		berBoolean = new BerBoolean(gs.simulation);
		length+=berBoolean.encode(baos, false);
		GooseDecoder.simulation.encode(baos);
		
		berInt = new BerInteger(gs.sqNum);
		length+=berInt.encode(baos, false);
		GooseDecoder.sqNum.encode(baos);
		
		length=0;//кодировка stNum
		berInt = new BerInteger(gs.stNum);
		length+=berInt.encode(baos, false);
		GooseDecoder.stNum.encode(baos);
		
		//кодировка T
		byte[] time = gs.t.getByteArray();
		baos.write(time);
		baos.write(8);
		GooseDecoder.T.encode(baos);
		
		length=0;//кодировка goID
		berString = new BerVisibleString(gs.goID);
		length+=berString.encode(baos, false);
		GooseDecoder.goID.encode(baos);
		
		length=0;//кодировка datSet
		berString = new BerVisibleString(gs.datSet);
		length+=berString.encode(baos, false);
		GooseDecoder.datSet.encode(baos);

		length=0;//кодировка timeAllowedToLive
		berInt = new BerInteger(gs.timeAllowedtoLive);
		length+=berInt.encode(baos, false);
		GooseDecoder.timeAllowedToLive.encode(baos);
		
		length=0;//кодировка goCBRef
		berString = new BerVisibleString(gs.gocbRref);
		length+=berString.encode(baos, false);
		GooseDecoder.goCBRef.encode(baos);
		
		bLength = new BerLength();
		bLength.encodeLength(baos, baos.getArray().length);	
		GooseDecoder.goosePdu.encode(baos);
		
		//кодировка длины пакета
		int PacketLength =  baos.getArray().length + rawData.length-14;
		if (PacketLength==127 || PacketLength==128) {PacketLength--;}
		//запись преамбулы после длины
		baos.write(Arrays.copyOfRange(rawData, 18, 22));
		//запись длины
		byte[] ab = ByteBuffer.allocate(4).putInt(PacketLength).array();
		//запись преамбулы до длины
		baos.write(Arrays.copyOfRange(ab, 2, 4) );
		baos.write(Arrays.copyOfRange(rawData, 0, 16));
		
		//получение готового массива Byte для EthernetPacket
		byte[] code = baos.getArray();
				
		try {
			gooseEthernetPacket = EthernetPacket.newPacket(code);
		} catch (IllegalRawDataException e) {
			e.printStackTrace();
		}
		
	}
	

	// циклическая отправка GOOSE сообщения с заданным интервалом времени
	/**Осуществляет циклическую отправку GOOSE сообщения с заданным интервалом времени
	 * @throws IOException
	 */
	public void SendGoose() throws IOException{
			gooseScheduler.execute(sender);
		}
	
	// Для ТЕСТА: циклическая одной копии GOOSE-сообщения в течение 60 секунд с интервалом = 2 сек.
	/**
	 *@deprecated 
	 */
	public void SendGoose_test(){
//	     final Runnable beeper = new Runnable() {
//	         public void run() { 
//	        	System.out.println("beep");      	
//	 			for (PcapNetworkInterface iface : ifs){
//	 				if (iface.getName().equals(ifname)){
//	 					activeInterface = iface;
//	 					break;
//	 				}
//	 			}
//	 			System.out.println("beep2");
//	     		try {
//					handle = activeInterface.openLive(65536, PromiscuousMode.PROMISCUOUS,50);
//					handle.sendPacket(gooseEthernetPacket);
//				    System.out.println("beep3");
//				} 
//	     		catch (PcapNativeException | NotOpenException e) {
//					e.printStackTrace();
//				}
//	    	 }
//	     };
//	       
//       final ScheduledFuture<?> beeperHandle =  gooseScheduler.scheduleAtFixedRate(beeper, 2, 2, SECONDS);
//	   gooseScheduler.schedule(new Runnable() {			
//		   public void run() {
//			   beeperHandle.cancel(true);
//		   }
//	   },1*60, SECONDS);
//	 
	}
	
	
	/**Преобразует строку 16чных чисел в массив байт
	 * @param s строка HEX (например, 14a4d446e)
	 * @return массив байт
	 */
	public static byte[] hexStringToByteArray(String s) {
	    byte[] b = new byte[s.length() / 2];
	    for (int i = 0; i < b.length; i++) {
	      int index = i * 2;
	      int v = Integer.parseInt(s.substring(index, index + 2), 16);
	      b[i] = (byte) v; 
	    }
	    return b;
	}
	
	/**Преобразует стандартную запись мак-адреса к массиву Byte
	 * @param s MAC адрес
	 * @return массив байт
	 */
	public static byte[] macStringToByteArray(String s) {
	    byte[] b = new byte[6];
	    int j=0;
	    for (int i = 0; i < b.length; i++) {
	      int v = Integer.parseInt(s.substring(j, j+ 2), 16);
	      b[i] = (byte) v;
	      j=j+3;
	    }
	    return b;
	}
	
	
	/** Преобразует BitSet к массиву Byte
	 * @param bits битсет
	 * @return массив байт
	 */
	public static byte[] toByteArray(BitSet bits) {
	    byte[] bytes = new byte[(bits.length()+7)/8];
	    for (int i=0; i<bits.length(); i++) {
	        if (bits.get(i)) {
	            bytes[bytes.length-i/8-1] |= 1<<(i%8);
	        }
	    }
	    return bytes;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractNode#start()
	 */
	@Override
	public void start() throws Exception {
		//Операции, которые нужно выполнить после загрузки параметров из файла настроек
		//Здесь, например, нужно используя объект DataSet принятый из настроек создать 
		//gsMessage и шаблон сообщения на его основе. Что-то вроде
//		GooseMessage gm = new GooseMessage();
//		gm.DataSet = (GooseValueDefinition[]) dataSet
//				.toArray(new GooseValueDefinition[dataSet.size()]);
//		gm.datSet=...
//		...
//		PrepareGoose(gm);
		//Вместо расшифровки сообщения
		
		
		macDstByte = macStringToByteArray(macDst);
		macSourceByte = macStringToByteArray(macSource);
		InputStream stream = null;
		stream=this.getClass().getResourceAsStream(resourcePath);
		int size = stream.available();
		rawData = new byte[size];
		stream.read(rawData);
		for (int i=0;i<macDstByte.length+macSourceByte.length;i++){
			if (i<macDstByte.length) rawData[i]=macDstByte[i];
			else rawData[i]=macSourceByte[i-macDstByte.length];
		}
		
		templateMessage = new GooseMessage();
		templateMessage.DataSet = (GooseValueDefinition[]) dataSet
				.toArray(new GooseValueDefinition[dataSet.size()]);
		templateMessage.datSet = dataSetName;
		templateMessage.goID = goID;
		templateMessage.numDatasetEnries = 2*dataSet.size();
		templateMessage.gocbRref = gocbRef;
		templateMessage.confRev = confRev;
		templateMessage.t = new Timestamp(Calendar.getInstance().getTimeInMillis());
		templateMessage.ndsCom = ndsCom;
		templateMessage.stNum=0;
		templateMessage.sqNum=0;
		templateMessage.timeAllowedtoLive=(long) 2000;
		
		sender = new Runnable() {			
			@Override
			public void run() {
				if (!paused){
					int seq = templateMessage.sqNum;
					if (seq < delays.length - 1) {
						delay = seq;
						timeAllowed = seq + 1;
					} else {
						delay = delays.length - 1;
						timeAllowed = delays.length - 1;
					}
					future = gooseScheduler.schedule(sender, delays[delay],
							TimeUnit.MILLISECONDS);
					templateMessage.timeAllowedtoLive = (long) delays[timeAllowed];
					try {
						PrepareGoose(templateMessage);
					} catch (IEDException iedex) {
						logger.warn("Ошибка входных данных для goose пакета");
					} catch (IOException e) {
						e.printStackTrace();
						logger.warn("Невозможно подготовить goose пакет");
					} finally {

					}
					try {
						ethernetSender.sendPacket(gooseEthernetPacket);
						templateMessage.sqNum++;
					} catch (PcapNativeException | NotOpenException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						logger.warn("Ошибка при отправке пакета");
					}
				}
			}
		};
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractNode#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractNode#setName(java.lang.String)
	 */
	@Override
	public void setName(String name) {
		this.name=name;
		
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractGooseInterface#getByIndex(int)
	 */
	@Override
	public GooseValue getByIndex(int index) {
		return dataSet.get(index);
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractGooseSender#dataSetUpdated(ru.smarteps.iec61850.GooseValue[])
	 */
	@Override
	public void dataSetUpdated(GooseValue[] gooseValueDefinitions) {		
			if (future!=null) future.cancel(true);
			try {
			templateMessage.stNum++;
			templateMessage.sqNum=0;
			templateMessage.t = new Timestamp(Calendar.getInstance().getTimeInMillis());
			for (int i=0; i<gooseValueDefinitions.length; i++){
				templateMessage.DataSet[i].val = gooseValueDefinitions[i].val;
			}
			SendGoose();
		} catch (IOException e) {
			//TODO: handle me
		}
	}

	/**Получает МАС адрес назначения
	 * @return МАС адрес назначения
	 */
	public String getMacDst() {
		return macDst;
	}

	/**Задает МАС адрес назначения
	 * @param macDst МАС адрес назначения
	 */
	public void setMacDst(String macDst) {
		this.macDst = macDst;
	}

	/**Получает МАС адрес источника
	 * @return МАС адрес источника
	 */
	public String getMacSource() {
		return macSource;
	}

	/**Задает МАС адрес источника
	 * @param macSource МАС адрес источника
	 */
	public void setMacSource(String macSource) {
		this.macSource = macSource;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractGooseInterface#getDataSetName()
	 */
	@Override
	public String getDataSetName() {
		return dataSetName;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractGooseInterface#setDataSetName(java.lang.String)
	 */
	@Override
	public void setDataSetName(String dsName) {
		this.dataSetName = dsName;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractGooseInterface#setDataSet(ru.smarteps.iec61850.DataSet)
	 */
	@Override
	public void setDataSet(DataSet ds) {
		this.dataSet = ds;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractGooseInterface#getDataSet()
	 */
	@Override
	public DataSet getDataSet() {
		return dataSet;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractGooseSender#setEthernetSender(ru.smarteps.iec61850.EthernetSender)
	 */
	@Override
	public void setEthernetSender(EthernetSender es) {
		this.ethernetSender = es;
	}
		
	/**Получает значение поля goID
	 * @return значение поля goID
	 */
	public String getGoID() {
		return goID;
	}

	/**Задает значение поля goID
	 * @param goID значение поля goID
	 */
	public void setGoID(String goID) {
		this.goID = goID;
	}

	/**Получает значение поля gocbRef
	 * @return значение поля gocbRef
	 */
	public String getGocbRef() {
		return gocbRef;
	}

	/**Задает значение поля gocbRef
	 * @param gocbRref значение поля gocbRef
	 */
	public void setGocbRef(String gocbRref) {
		this.gocbRef = gocbRref;
	}

	/**Получает значение поля ndsCom
	 * @return значение поля ndsCom
	 */
	public Boolean getNdsCom() {
		return ndsCom;
	}

	/**Задает значение поля ndsCom
	 * @param ndsCom значение поля ndsCom
	 */
	public void setNdsCom(Boolean ndsCom) {
		this.ndsCom = ndsCom;
	}

	/**Получает значение поля confRev
	 * @return значение поля confRev
	 */
	public int getConfRev() {
		return confRev;
	}

	/**Задает значение поля confRev
	 * @param значение поля confRev
	 */
	public void setConfRev(int confRev) {
		this.confRev = confRev;
	}

	@Override
	public void stop() {
		gooseScheduler.shutdown();
	}

	@Override
	public void pause() {
		paused = true;
	}

	@Override
	public void unpause() {
		paused = false;
		
	}

	@Override
	public int getPauseState() {
		return paused?AbstractGooseSender.PAUSED:AbstractGooseSender.UNPAUSED;
	}
}

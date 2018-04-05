package ru.smarteps.iec61850;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ru.smarteps.iec61850.interfaces.AbstractListener;

/**Класс приема пакетов SV МЭК 61850 в режиме "24". Работает с сетевыми интерфейсами через библиотеку libpcap/winpcap.
 * Обработка пакетов осуществляется в многопоточном режиме. Во время обработки создается очередь из последних
 * принятых пактов длиной 400 шт. (по умолчанию).
* @author Andreev
*/
public class EthernetListener24 implements AbstractListener {
	/**
	 * Приемник журнала событий
	 */
	final Logger logger = LoggerFactory.getLogger(this.getClass());
	/**
	 * Список сетевых интерфейсов 
	 */
	List<PcapNetworkInterface> ifs;
	/**
	 * Активный интерфейс
	 */
	private PcapNetworkInterface activeInterface;
	/**
	 * Приемник пакетов
	 */
	private PacketListener svListener;
	/**
	 * Обработчик событий приема пакета
	 */
	private PcapHandle handle;
	/**
	 * Пул потоков обработки пакетов
	 */
	private ExecutorService pool;
	/**
	 * Коэффициент пропорциональности
	 */
	double[] kprop;
	/**
	 * Смещение
	 */
	double[] offset;
	/**
	 * Имя сетеового интерфейса по умолчанию
	 */
	protected String iface="eth0";
	/**
	 * Предфильтр по этому МАС адресу
	 */
	protected String mac="01:0C:CD:04:00:00";
	/**
	 * Размер буфера пакетов
	 */
	protected int bufferSize=400;
	/**
	 * Имя узла (для конфигурации XML)
	 */
	protected String name="SvListener1";
	/**
	 * Очередь для приема пакетов
	 */
	private LinkedList<byte[]> queue = new LinkedList<byte[]>();
	/**
	 * Буфер приема пакетов
	 */
	private byte[][] buffer;
	/**
	 * Позиция в пакете
	 */
	private int pos=0;
	
	/**
	 * Конструктор по умолчанию
	 * 
	 * * <pre>
	 * {@code
	 * <listener name="sv0"
	 *			config-class="ru.smarteps.iec61850.EthernetListener24"
	 *			iface="\\Device\\NPF_{451AC81E-FC1A-4642-952D-77D8451F5CB8}"
	 *			mac="01:0C:CD:04:00:00"
	 *			bufferSize="400"
	 *			kprop="0.01,0.01,0.01,0.01,0.01,0.01,0.01,0.01,0.01,0.01,
	 *					0.01,0.01,0.01,0.01,0.01,0.01,0.01,0.01,0.01,0.01,
	 *					0.01,0.01,0.01,0.01"
	 *			offset="0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
	 *					0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
	 *					0.0,0.0,0.0,0.0">
	 *	</listener>
	 * }
	 * </pre>
	 * 
	 */
	public EthernetListener24(){
	}
	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractNode#start()
	 */
	@Override
	public void start() throws Exception{
		buffer = new byte[bufferSize][];
		try {
			ifs = Pcaps.findAllDevs();
		} catch (PcapNativeException e) {
			logger.error("Ошибка загрузки библиотеки pcap");
			logger.error(e.getMessage());
			throw e;
		}
		catch(Exception ex){
			logger.error("Unexpected error: "+ex.getMessage());
			throw ex;
		}
		if (ifs.size()==0) throw new Exception("Не найдены сетевые интерфейсы");
		for (PcapNetworkInterface intrfc : ifs){
			if (intrfc.getName().equals(iface)){
				activeInterface = intrfc;
				break;
			}
		}
		if (activeInterface==null) {
			for (PcapNetworkInterface iface : ifs){
				logger.error("Интерфейс: " + iface.getName() + " | IP:" + iface.getAddresses() );
			}
			throw new Exception("Невозможно получить сетевой интерфейс "+iface);
			}
		handle = activeInterface.openLive(65536, PromiscuousMode.PROMISCUOUS,50);
		if (handle == null){
			logger.error("Невозможно открыть сетевой интерфейс");
			throw new Exception("Невозможно открыть сетевой интерфейс");
		}
		if (mac==null){
			logger.error("Неверный параметр 'mac' в конфигурации");
			throw new Exception("Неверный параметр 'mac' в конфигурации");
		}
		String filter = "ether dst "+mac;
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		
		pool = Executors.newFixedThreadPool(10);
		
		svListener = new PacketListener() {
			
			@Override
			public void gotPacket(Packet arg0) {
				synchronized (buffer) {
					if (pos>=bufferSize){
						pos-=bufferSize;
					}
					buffer[pos]=arg0.getRawData();
					pos++;
				}
				
			}
		};
		
		new Thread(
				new Runnable(){
					@Override
					public void run() {
						try {
							handle.loop(0, svListener, pool);
						} catch (PcapNativeException | InterruptedException
								| NotOpenException e) {
							logger.error(e.getMessage());
						}
					}
				}).start();
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
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#getData()
	 */
	@Override
	public LinkedList<byte[]> getData() throws BadDataException {
		return getPacketQueue();
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#getKi()
	 */
	@Override
	public float getKi() {
		// TODO Auto-generated method stub
		return 0;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#getKu()
	 */
	@Override
	public float getKu() {
		// TODO Auto-generated method stub
		return 0;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#getOffsetI()
	 */
	@Override
	public float getOffsetI() {
		// TODO Auto-generated method stub
		return 0;
	}

	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#getOffsetU()
	 */
	@Override
	public float getOffsetU() {
		// TODO Auto-generated method stub
		return 0;
	}
	
	/** Получает коэффициент пропорциональности
	 * @return значение
	 */
	public double[] getKprop(){
		return null;
	}

	/** Задает коэффициент пропорциональности
	 * @param val Значение
	 */
	public void setKprop(double[] val){
		this.kprop = val;
	}
	
	/** Получает смещение
	 * @return Значение
	 */
	public double[] getOffset(){
		return null;
	}
	/** Задает смещение
	 * @param val Значение
	 */
	public void setOffset(double[] val){
		this.offset=val;
	}

	/** Получает имя сетевого интерфейса
	 * @return имя сетевого интерфейса
	 */
	public String getIface() {
		return iface;
	}

	/** Задает имя сетевого интерфейса
	 * @param iface имя сетевого интерфейса
	 */
	public void setIface(String iface) {
		this.iface = iface;
	}

	/** Получает МАС для предфильтра
	 * @return МАС для предфильтра
	 */
	public String getMac() {
		return mac;
	}

	/** Задает МАС для предфильтра
	 * @param mac МАС для предфильтра
	 */
	public void setMac(String mac) {
		this.mac = mac;
	}

	/** Получает размер буфера пакетов
	 * @return размер буфера пакетов
	 */
	public int getBufferSize() {
		return bufferSize;
	}

	/**Задает размер буфера пакетов
	 * @param bufferSize размер буфера пакетов
	 */
	public void setBufferSize(int bufferSize) {
		this.bufferSize = bufferSize;
	}
	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#stop()
	 */
	@Override
	public synchronized void stop() {
		logger.info("Shutting down "+iface);
		if (handle != null && handle.isOpen()) {
			try {
				handle.breakLoop();
				handle.close();
				pool.shutdown();
			} catch (NotOpenException e) {
				logger.error("Ошибка закрытия интерфейса: "+e.getMessage());
			}

		}
		logger.info("Отключение " +iface + "завершено");
	}

	/**Получает копию буфера последних пакетов. При приеме новых пакетов полученный объект не изменяется.
	 * 
	 * @return копия буфера приема пакетов
	 * @throws BadDataException
	 */
	@SuppressWarnings("unchecked")
	public LinkedList<byte[]> getPacketQueue() throws BadDataException {
		//TODO: Избавиться от LinkedList в пользу обычного массива
		queue.clear();
		if (buffer == null) throw new BadDataException("Не инициализирован EthernetListener "+name);
		for (int i=pos; i<bufferSize; i++){
			if (buffer[i]!=null){
				queue.add(buffer[i]);
			}
		}
		for (int i=0; i<pos; i++){
			if (buffer[i]!=null){
				queue.add(buffer[i]);
			}
		}
		return (LinkedList<byte[]>) queue.clone();
	}
	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#getK(int)
	 */
	@Override
	public float getK(int slot) {
		if (kprop.length>slot){
			return (float)kprop[slot];
		}
		return 0;
	}
	/**
	 * @see ru.smarteps.iec61850.interfaces.AbstractListener#getOffset(int)
	 */
	@Override
	public float getOffset(int slot) {
		return (float)offset[slot];
	}

	
}

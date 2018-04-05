package ru.smarteps.iec61850;

import ru.smarteps.iec61850.interfaces.AbstractGooseInterface;

/**Класс связывающий тэг данных с их положением в составе DataSet
 */
public class GooseValueDefinition extends GooseValue{

	/**
	 * Порядковый номер сигнала в DataSet
	 */
	public int index;
	/**
	 * Инетрфейс, через который осуществляется прием или прередача данных
	 */
	public AbstractGooseInterface gooseInterface;
	/**
	 * Имя тэга
	 */
	public String tag;
	
	/**
	 * Конструктор по умолчанию
	 * 
	 * <pre>
	 * {@code
	 * <value
	 * 	config-class="ru.smarteps.iec61850.GooseValueDefinition"
	 * 	type="boolean" tag="sseBreaker105stateSet" val="true"/>
	 * }
	 * </pre>
	 */
	public GooseValueDefinition(){
		
	}
	
	/**Конструктор с параметром
	 * @param gv элемент данных DataSet
	 */
	public GooseValueDefinition(GooseValue gv) {
		this.quality = gv.quality;
		this.t = gv.t;
		this.val = gv.val;
		this.valtype = gv.valtype;
	}
	
	/**Получает имя тэга
	 * @return имя тэга
	 */
	public String getTag(){
		return tag;
	}
	
	/**Задает имя тэга
	 * @param tag имя тэга
	 */
	public void setTag(String tag){
		this.tag=tag;
	}
	/**Задает новое значение
	 * @param o новое значение
	 */
	public void setVal(String o){
		if (valtype==null) val=o;
		if (valtype==Boolean.class){
			val=Boolean.getBoolean(o);
		}
		else if(valtype==Float.class){
			val=Float.parseFloat(o);
		}
		else if(valtype==Integer.class){
			val=Integer.parseInt(o);
		}
		
	}
	
	/**Получает текущее значение
	 * @return текущее значение
	 */
	public Object getVal(){
		return val;
	}
}

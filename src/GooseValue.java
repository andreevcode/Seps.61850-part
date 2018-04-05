package ru.smarteps.iec61850;

import java.util.BitSet;

/**Класс хранящий значения поля данных GOOSE сообещения в составе DataSet
 *
 */
public class GooseValue  {
	/**
	 * Качестов сигнала
	 */
	public BitSet quality=new BitSet(0);
    /**
     * Значение поля
     */
    public Object val =null;  
    /**
     * Тип данных поля
     */
    public Class valtype=null; 
    /**
     * Время приема сигнала
     */
    public java.sql.Timestamp t = null; 
    
	/**Получает тип данных
	 * @return тип данных
	 */
	public String getType() {
		return valtype.toString();
	}
	/**Задает тип данных
	 * @param type тип данных
	 */
	public void setType(String type) {
		if (type.equalsIgnoreCase("boolean")){
			valtype = Boolean.class;
			if(val!=null) val = Boolean.getBoolean((String)val);
		}
		else if (type.equalsIgnoreCase("float")){
			valtype = Float.class;
			if(val!=null) val = Float.parseFloat((String)val);
		}
		else if (type.equalsIgnoreCase("integer")){
			valtype = Integer.class;
			if(val!=null) val = Integer.parseInt((String)val);
		}
		
	}
}


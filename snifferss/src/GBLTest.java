import java.awt.*;
import java.awt.event.*;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import GBC.GBC;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import jpcap.JpcapCaptor;
import jpcap.packet.*;
import jpcap.NetworkInterface;

public class GBLTest {

	/**
	 * @param args
	 */

	public static void main(String[] args)
	{	
		firstThread firstthread = new firstThread();
		firstthread.start();		
	}
}

 class firstThread extends Thread{
	public firstThread(){}
	public void run(){
		EventQueue.invokeLater(new Runnable()
		{
			public void run()
			{
				FrontFrame frame;
				try {
					frame = new FrontFrame();
					frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
					frame.setVisible(true);		
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}					
			}
		});
	}
}

class FrontFrame extends JFrame
{
	public JComboBox card;
	static public int networkinterfaceNumber;
	public Sniffer sniffer = new Sniffer();
	//public Sniffer1 sniffer1 = new Sniffer1();
	public boolean flag = true;
	private JButton startbutton;
	private JButton endbutton;	
	private DefaultTableModel tablemodel;
	private JTable table;
	public MyThread thread = null;
	
//	@SuppressWarnings("unchecked")
	public FrontFrame() throws IOException
	{
		setTitle("sniffer");
		setSize(800,600);
		Toolkit kit = Toolkit.getDefaultToolkit(); // ���幤�߰� 
		Dimension screenSize = kit.getScreenSize(); // ��ȡ��Ļ�ĳߴ� 
		int screenWidth = screenSize.width/2; // ��ȡ��Ļ�Ŀ�
		int screenHeight = screenSize.height/2; // ��ȡ��Ļ�ĸ�
		int height = this.getHeight();
		int width = this.getWidth(); 
		setLocation(screenWidth-width/2, screenHeight-height/2);
		GridBagLayout layout = new GridBagLayout();
		setLayout(layout);		
		
		//������ǩ�������˵�
		JLabel cardlabel = new JLabel("������");	
		card = new JComboBox(sniffer.getDevice());	
		
		//��ϸ��Ϣ�ͱ�ͷ
		JLabel infolabel = new JLabel("��ϸ��Ϣ��");
		JLabel headlabel = new JLabel("��ͷ��");
		
		//��ť 
		startbutton = new JButton("  ��ʼץȡ  ");
		endbutton = new JButton("  ����ץȡ  ");
		JButton searchbutton = new JButton("���ݰ���ѯ");
		JButton rebutton = new JButton("IP��Ƭ���� ");
		JButton savebutton = new JButton("����Ϊ�ļ�");
		JButton filterbutton = new JButton("  ������       ");
				
		//ץ���İ�
		String[] columnNames = {"���","ʱ��","Դ��ַ","Ŀ�ĵ�ַ","Э������","��Ϣ","����"};
		String[][] tableVales = null;
		tablemodel = new DefaultTableModel(tableVales,columnNames);
		table = new JTable(tablemodel);
		JScrollPane infoscrollPane = new JScrollPane(table);
		
		
		 ///��ͷ�������
		table.getColumnModel().getColumn(0).setPreferredWidth(10);
		table.getColumnModel().getColumn(1).setPreferredWidth(90);
		table.getColumnModel().getColumn(4).setPreferredWidth(40);
		table.getColumnModel().getColumn(5).setPreferredWidth(40);
		table.getColumnModel().getColumn(6).setPreferredWidth(20);
		
		
		//��ʾ��ϸ��Ϣ�ͱ�ͷ
		final JTextArea text = new JTextArea();
		text.setLineWrap(true); 
		JScrollPane textscrollPane = new JScrollPane(text);
		final JTextArea head = new JTextArea();
		head.setLineWrap(true); 
		JScrollPane headscrollPane = new JScrollPane(head);
		final JTextArea hex = new JTextArea();
		hex.setLineWrap(true); 
		JScrollPane hexscrollPane = new JScrollPane(hex);
		
		
		///�������һ�е���ϸ��Ϣ���ı������
		/*��ʱ��������ʾ������ϸ��Ϣ*/
		table.addMouseListener(new java.awt.event.MouseAdapter()
        {
            public void mouseClicked(java.awt.event.MouseEvent e)
            {
                Point mousepoint;    
                int detailindex;
                mousepoint =e.getPoint();                
                detailindex = table.rowAtPoint(mousepoint);   
                text.setText(Sniffer.infodata[detailindex]);
                hex.setText(Sniffer.hexdata[detailindex]);
                head.setText(Sniffer.iphead[detailindex] + Sniffer.subhead[detailindex]);
                repaint();
            }
        });

		//����
		add(infolabel, new GBC(2,3,1,3).setAnchor(GBC.NORTHWEST).setIpad(50, 120));
		add(headlabel, new GBC(0,3,1,3).setAnchor(GBC.NORTH).setIpad(50, 120));
		add(cardlabel, new GBC(1,0).setAnchor(GBC.NORTH).setIpad(50, 50));
		add(card, new GBC(2,0).setAnchor(GBC.CENTER).setIpad(80, 20));
		add(startbutton, new GBC(3,1).setAnchor(GBC.EAST).setIpad(50, 50));
		add(endbutton, new GBC(3,2).setAnchor(GBC.EAST).setIpad(50, 50));
		add(filterbutton, new GBC(3,3).setAnchor(GBC.EAST).setIpad(50, 50));
		add(searchbutton, new GBC(3,4).setAnchor(GBC.EAST).setIpad(50, 50));
		add(rebutton, new GBC(3,5).setAnchor(GBC.EAST).setIpad(50, 50));
		add(savebutton, new GBC(3,6).setAnchor(GBC.EAST).setIpad(50, 50));		
		add(infoscrollPane, new GBC(0,1,3,3).setAnchor(GBC.NORTH).setIpad(580, 180));
		add(hexscrollPane, new GBC(2,5,1,2).setAnchor(GBC.EAST).setIpad(380, 120));
		add(headscrollPane, new GBC(0,4,2,3).setAnchor(GBC.EAST).setIpad(200, 200));
		add(textscrollPane, new GBC(2,4,1,1).setAnchor(GBC.EAST).setIpad(380, 80));			
	
		//����
		ActionListener devicelistener = new DeviceAction();
		ActionListener capturelistener = new CaptureAction();
		ActionListener endlistener = new EndAction();
		ActionListener rebuttonlistener = new RebuttonAction();
		ActionListener savebuttonlistener = new SavebuttonAction();
		
		card.addActionListener(devicelistener);
		startbutton.addActionListener(capturelistener);
		endbutton.addActionListener(endlistener);
	//	searchbutton.addActionListener(listener);
		rebutton.addActionListener(rebuttonlistener);
		savebutton.addActionListener(savebuttonlistener);
	//	filterbutton.addActionListener(listener);		
		
		System.out.println("end");
		
	}
	
	private class MyThread extends Thread
	{
		public MyThread(){}
		public void run(){
			while(flag){				
		         try {
		        	 try {
						tablemodel.addRow(sniffer.getInfo(sniffer.getpacket()));
					} catch (IOException e) {
						e.printStackTrace();
					}
					    tablemodel.fireTableDataChanged();
						table.invalidate();
						Thread.sleep(100);
				         table.repaint();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	
	//�����ʼץȡ
	private class CaptureAction implements ActionListener
	{  
		public void actionPerformed(ActionEvent event)
		{    
			flag = true;
			thread = new MyThread();
			thread.start();
			table.repaint();
		}	
	}

	//�������ץȡ
	private class EndAction implements ActionListener
	{		
		public void actionPerformed(ActionEvent event)
		{
		//	if(event.g)
/////			thread.stop();
			thread = null;
			flag = false;
			System.out.println("click end");
		}	
	}
	
	//��ȡ������Ϣ
	private class DeviceAction implements ActionListener
	{		
		public void actionPerformed(ActionEvent event)
		{
			networkinterfaceNumber = card.getSelectedIndex();
		}	
	}
	
	//�����������
	private class RebuttonAction implements ActionListener
	{  
		public void actionPerformed(ActionEvent event)
		{    
			JFrame frame1 = new JFrame("IP��Ƭ����");
			frame1.setLocationRelativeTo(card);
			frame1.setSize(500, 300);
			
			final JTextArea text = new JTextArea();
			text.setLineWrap(true); 
			JScrollPane textscrollPane = new JScrollPane(text);
			text.setText(sniffer.rebuild());
			frame1.getContentPane().add(textscrollPane);
			frame1.setVisible(true);			
		}	
	}

	//�������
	private class SavebuttonAction implements ActionListener{
		public void actionPerformed(ActionEvent event){
			File file = new File("d:/result.doc");
			FileWriter fw;
			try {
				fw = new FileWriter(file);
				BufferedWriter bw = new BufferedWriter(fw);
				for(int i = 0; i < Sniffer.count; i++){
					if(table.isRowSelected(i)==true){
						if(Sniffer.list.get(i) instanceof jpcap.packet.IPPacket){
						    bw.write(String.valueOf(i) + ":\n" + Sniffer.iphead[i] + Sniffer.subhead[i] + 
								    "���ݣ�\n" + Sniffer.infodata[i] + "\n\n");		
						}else if(Sniffer.list.get(i) instanceof jpcap.packet.ARPPacket){
					 	    bw.write(String.valueOf(i) + ":\n" + Sniffer.subhead[i] + 
					 			   "���ݣ�\n" + Sniffer.infodata[i] + "\n\n");	
						}else{
						    bw.write(String.valueOf(i) + ":\n" + "���ݣ�\n" + Sniffer.infodata[i] + "\n\n");	
						}
					}  
				}
				bw.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}	       
		}		
	}
}

class Sniffer
{
	public static ArrayList list = new ArrayList();
	public static String[] infodata = new String[200];
	//int infodatacount = 0;
	public static String[] hexdata = new String[200];
	//int hexdatacount = 0;
	public NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	public static int count = 0;
	public String ss = new String();
	public static String[] iphead = new String[200];
	public static String[] subhead = new String[200];
	
	public String[] getDevice()
	{
		String[] str = new String[devices.length]; 
		for (int i = 0; i < devices.length; i++)
			str[i] = devices[i].description;
		return str;
	}
	
	//ת16����
	public String BytesToHexString(byte[] b)
	{
		String hs = "";
	        String stmp = "";
	        for(int n = 0;n < b.length;n++)
	        {
	            stmp = (Integer.toHexString(b[n] & 0XFF));
	            if(stmp.length() == 1) 
	            	hs = hs + "0" + stmp;
	            else 
	            	hs = hs + stmp;
	        }
	        return hs.toUpperCase();   
	}
	
	//ץ��
	public Packet getpacket() throws IOException{
		JpcapCaptor captor = JpcapCaptor.openDevice(devices[FrontFrame.networkinterfaceNumber], 65535, false, 20);
		Packet packet = captor.getPacket();
		while(packet == null)
			packet = captor.getPacket();
		list.add(packet);
		
		return packet;
	}
	
	//�õ���ͷ(���ú���ȡ��)���������ϸ��Ϣ
	public String[] getInfo(Packet packet) throws IOException
	{	
		String s[] = new String[7];
	//	String str[] = new String[2000];//����65536��
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		gethead(packet);
		getiphead(packet);

		//��ϸ��Ϣ�����16����
		if(packet != null && packet.data != null){
			infodata[count] = "��Ϣ��" + "\n" + new String(packet.data, "UTF-8");
			hexdata[count] = "16���ƣ�\n" + BytesToHexString(packet.data);
		}	
		
        //TCP�� ��ͷ��Э�����
		if(packet instanceof jpcap.packet.TCPPacket){
			TCPPacket p = (TCPPacket)packet;
			s[0] = String.valueOf(count);
			s[1] = String.valueOf(df.format(new Date()));
			s[2] = String.valueOf(p.src_ip);
			s[3] = String.valueOf(p.dst_ip);
			s[4] = "TCP";
			s[5] = String.valueOf(Arrays.toString(p.data));
			s[6] = String.valueOf(p.length);			
		//	System.out.println(str);
		}
		//UDP��
		else if(packet instanceof jpcap.packet.UDPPacket){
			UDPPacket p=(UDPPacket)packet; 
			s[0] = String.valueOf(count);
			s[1] = String.valueOf(df.format(new Date()));
			s[2] = String.valueOf(p.src_ip);
			s[3] = String.valueOf(p.dst_ip);
			s[4] = "UDP";
			s[5] = String.valueOf(Arrays.toString(p.data));
			s[6] = String.valueOf(p.length);
		}
		//ICMP��
		else if(packet instanceof jpcap.packet.ICMPPacket){
			ICMPPacket p=(ICMPPacket)packet; 
			s[0] = String.valueOf(count);
			s[1] = String.valueOf(df.format(new Date()));
			s[2] = String.valueOf(p.src_ip);
			s[3] = String.valueOf(p.dst_ip);
			s[4] = "ICMP";
			s[5] = String.valueOf(Arrays.toString(p.data));	
			s[6] = String.valueOf(p.length);
		}
		//ARP��
		else if(packet instanceof jpcap.packet.ARPPacket){
			ARPPacket p=(ARPPacket)packet;
			s[0] = String.valueOf(count);
			s[1] = String.valueOf(df.format(new Date()));
			s[2] = String.valueOf(p.getSenderHardwareAddress());
			s[3] = String.valueOf(p.getTargetHardwareAddress());
			s[4] = "ARP";
			s[5] = String.valueOf(Arrays.toString(p.data));	
			s[6] = String.valueOf(p.len);
	    }else{
	    	s[0] = String.valueOf(count);
	    	s[1] = String.valueOf(df.format(new Date()));
	    	s[4] = "������";
	    	s[5] = String.valueOf(Arrays.toString(packet.data));	
			s[6] = String.valueOf(packet.len);
	    }
		count++;
		return s;//����е�����		
	}
	
	//ȡ��IP��ͷ
	public String getiphead(Packet packet) throws IOException{
		//IP��ͷ
		//Packet packet = getpacket();
		count = list.indexOf(packet);
		if((packet instanceof jpcap.packet.IPPacket)){
		    IPPacket ipp = (IPPacket)packet;
		    iphead[count] = "IP��ͷ\n" + "�汾��" + String.valueOf(ipp.version) + "\n" +
		         "ͷ���ȣ� "+String.valueOf(ipp.header.length) + "\n" +
		         "�������ͣ� "+String.valueOf(ipp.header[1]) + "\n" +
		         "�ܳ��ȣ�"+String.valueOf(ipp.len) + "\n" +
		         "��ʶ�� "+String.valueOf(ipp.ident) + "\n" +
		         "DF��"+String.valueOf(ipp.dont_frag) + "\n" +
		         "MF��"+String.valueOf(ipp.more_frag) + "\n" +
		         "�ֶ�ƫ������ "+String.valueOf(ipp.offset) + "\n" +
		         "�����ڣ� "+String.valueOf(ipp.header[8]) + "\n" +
		         "Э�飺"+String.valueOf(ipp.header[9]) + "\n" +
		         "ͷУ��ͣ� "+String.valueOf(ipp.header[10])+ String.valueOf(ipp.header[11]) + "\n" +
		         "Դ��ַ��"+String.valueOf(ipp.src_ip) + "\n" +
		         "Ŀ�ĵ�ַ��"+String.valueOf(ipp.dst_ip) + "\n" +
		         "ѡ� "+String.valueOf(ipp.option) + "\n\n";
		}else{
			iphead[count] = "��ip��ͷ\n\n ";
		}
		return iphead[count];
	}
	
	//ȡ��������ͷ
	public String gethead(Packet packet) throws IOException{
	//	Packet packet = getpacket();
		count = list.indexOf(packet);
		if(packet instanceof jpcap.packet.TCPPacket){
			TCPPacket p = (TCPPacket)packet;
			subhead[count] = "TCP��ͷ\n"+"Դ�˿ںţ�"+String.valueOf(p.src_port)+"\n"+
	          "Ŀ�Ķ˿ںţ�"+String.valueOf(p.dst_port)+"\n"+
	          "������ţ�"+String.valueOf(p.sequence)+"\n"+
	          "ȷ����ţ�"+String.valueOf(p.ack_num)+"\n"+
	          "ͷ�����ȣ�"+String.valueOf(p.header.length)+"\n"+
	          "URG��"+String.valueOf(p.urg)+"\n"+
	          "ACK��"+String.valueOf(p.ack)+"\n"+
	          "PSH��"+String.valueOf(p.psh)+"\n"+
	          "RST��"+String.valueOf(p.rst)+"\n"+
	          "SYN��"+String.valueOf(p.syn)+"\n"+
	          "FIN��"+String.valueOf(p.syn)+"\n"+
	          "���ڣ�"+String.valueOf(p.window)+"\n"+
	          "У��ͣ�"+String.valueOf(p.header[16])+String.valueOf(p.header[17])+"\n"+
	          "����ָ�룺"+String.valueOf(p.urgent_pointer)+"\n"+
	          //"��ѡ�"+String.valueOf(p.option.toString())+"\n"+
	          "��䣺"+String.valueOf(p.header[23]);
		}
		
		if(packet instanceof jpcap.packet.UDPPacket){
			UDPPacket p=(UDPPacket)packet; 
			subhead[count] = "UDP��ͷ\n"+"Դ�˿ڣ�"+ String.valueOf(p.src_port)+"\n"+
			          "Ŀ�Ķ˿ڣ�"+String.valueOf(p.dst_port)+"\n"+
			          "UDP����"+String.valueOf(p.len)+"\n"+
/*У��ͣ�*/	          "UDPУ���"+String.valueOf(p.header[6]+p.header[7]);
		}
		
		if(packet instanceof jpcap.packet.ICMPPacket){
			ICMPPacket p=(ICMPPacket)packet; 
			subhead[count] = "ICMP��ͷ"+"\n"+"���ͣ�"+String.valueOf(p.version)+"\n"+
			          "���룺"+String.valueOf(p.data)+"\n"+
			          "У���"+String.valueOf(p.header[2]+p.header[3]);
		}
		//ARP��
	    if(packet instanceof jpcap.packet.ARPPacket){
			ARPPacket p=(ARPPacket)packet;
			subhead[count] = "ARP��ͷ\n"+"Ӳ�����ͣ�"+String.valueOf(p.hardtype)+"\n"+
			          "Э�����ͣ�"+String.valueOf(p.prototype)+"\n"+
			          "MAC��ַ���ȣ�"+String.valueOf(p.caplen)+"\n"+
			          "Э���ַ���ȣ�"+String.valueOf(p.plen)+"\n"+
			          "�����룺"+String.valueOf(p.operation)+"\n"+
			          "���ͷ�MAC��ַ:"+String.valueOf(Arrays.toString(p.sender_hardaddr))+"\n"+
			          "���ͷ�IP��ַ:"+String.valueOf(Arrays.toString(p.sender_protoaddr))+"\n"+
			          "���շ�MAC��ַ:"+String.valueOf(Arrays.toString(p.target_hardaddr))+"\n"+
			          "���շ�IP��ַ:"+String.valueOf(Arrays.toString(p.target_protoaddr));
	    }
	    return subhead[count];
	}
	
	//IP��Ƭ����
	public String rebuild(){
		int[] id = new int[list.size()];
		int c = 0;
		String str = "";
		boolean flag = false;
	//	int j = 0;
		for(int i = 0 ; i < list.size(); i++){
			if(list.get(i) instanceof jpcap.packet.IPPacket){
				IPPacket ipp = (IPPacket)list.get(i);
				id[i] = ipp.ident;
			}
			else
				id[i] = -1;
		}
		Arrays.sort(id);
		for(int i = 0 ; i < list.size()-1; i++){
			if(id[i] == id[i+1] && id[i] != -1){
				flag = true;//��Ҫ����
				c = id[i];//��Ҫ����ı�ʶ��
				break;
			}
		}
		if(id[list.size()-2] == id[list.size()-1] && id[list.size()-2] != -1)
			flag = true;
		
		if(flag == false){
			str = "None.";
		}else{
			int[] reid = new int[list.size()];
			int max = 0;
			for(int i = 0 ; i < list.size()-1; i++){
				if(id[i] == c){
					reid[max] = i;
					max++;
				}//reid�д�Ű��ı��
			}
			
		//	int[] re = new int[max];//��Ҫ����ı��ĵ��±�����0
			int[] offset = new int[max];//�ֶ�ƫ����
			boolean[] mf = new boolean[max];//�жϷֶ��Ƿ����
			String[] data = new String[max];
			for(int i = 0 ; i < max; i++){
				IPPacket ipp = (IPPacket)list.get(reid[i]);
				offset[i] = ipp.offset;
				mf[i] = ipp.more_frag;
				data[i] = Arrays.toString(ipp.data);
			}
			
			//ð��
			int temp = 0;
			boolean b;
			String s = "";
	        for(int i = 0; i < max; i++){
	            for(int k = i; k < max; k++){
	                if(offset[i] > offset[k]){
	                    temp = offset[i];
	                    offset[i] = offset[k];
	                    offset[k] = temp;
	                    b = mf[i];
	                    mf[i] = mf[k];
	                    mf[k] = b;
	                    s = data[i];
	                    data[i] = data[k];
	                    data[k] = s;
	                }
	            }
	        }
	        
	        boolean iscomplete = true;
	        if(mf[max-1] == true)
	        	str = "The package is not complete.";
	        else{
	        	if(max >= 3){
	        	    for(int i = 0; i < max-2; i++){
	        		    if(offset[i+2] - offset[i+1] != offset[i+i] - offset[i]){
	        			//���������ƫ�����Ĳ�Ӧ��ͬ��������󳤶ȡ����������ܳ�������
	        			    str = "The package is not complete.";
	        			    iscomplete = false;
	        			    break;
	        		    }	        			
	        	    }
	        	    if(offset[max-1] - offset[max-2] > offset[max-2] - offset[max-3]){
	        		//�������������ƫ�����Ĳ�ض�С��֮ǰ�ġ�������ڣ�˵��֮ǰ���������ģ����Ǻ�벿������ȱ��
	        		    str = "The package is not complete.";
        			    iscomplete = false;
	        	    }
	        	    if(iscomplete == true){
	        		    for(int i = 0; i < max; i++){
	        			    str = str + data[i];
	        		    }
	        	    }
	        	}
	        	else if(max == 2){
	        		if(offset[0] == 0 && offset[1]-offset[0] < 65535)
	        			str = str + data[0] + data[1];
	        		else
	        			str = "The package is not complete.";
	        	}
	        }	        	
		}
		return str;
	}

	
}


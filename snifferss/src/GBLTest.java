import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.text.SimpleDateFormat;

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
		JButton rebutton = new JButton(" ��������   ");
		JButton savebutton = new JButton("   ����txt     ");
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
                try {
					head.setText(sniffer.getiphead() + sniffer.gethead());
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
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
		
		card.addActionListener(devicelistener);
		startbutton.addActionListener(capturelistener);
		endbutton.addActionListener(endlistener);
	//	searchbutton.addActionListener(listener);
	//	rebutton.addActionListener(listener);
	//	savebutton.addActionListener(listener);
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
						tablemodel.addRow(sniffer.getInfo());
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
			thread.stop();
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

}

class Sniffer
{
	public static String[] infodata = new String[50];
	int infodatacount = 0;
	public static String[] hexdata = new String[50];
	int hexdatacount = 0;
	public NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	public int count = 0;
	public String ss = new String();
	public String iphead = new String();
	public String subhead = new String();
	
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
	
	public Packet getpacket() throws IOException{
		JpcapCaptor captor = JpcapCaptor.openDevice(devices[FrontFrame.networkinterfaceNumber], 65535, false, 20);
		Packet packet = captor.getPacket();
		while(packet == null)
			packet = captor.getPacket();
		return packet;
	}
	
	//�õ���ͷ����ϸ��Ϣ
	public String[] getInfo() throws IOException
	{	
		String s[] = new String[7];
		String str[] = new String[2000];//����65536��
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Packet packet = getpacket();

		//��ϸ��Ϣ�����16����
		if(packet != null && packet.data != null){
			infodata[infodatacount] = "��Ϣ��" + "\n" + new String(packet.data, "UTF-8");
		//	System.out.println(infodata[infodatacount]);
			infodatacount++;
			hexdata[hexdatacount] = "16���ƣ�\n" + BytesToHexString(packet.data);
	        hexdatacount++;
		}
//		else
//			return null;	
		
        //TCP�� ��ͷ��Э�����
		if(packet instanceof jpcap.packet.TCPPacket){
			TCPPacket p = (TCPPacket)packet;
			s[0] = String.valueOf(count);
			s[1] = "";//String.valueOf(df.format(System.currentTimeMillis()));
			s[2] = String.valueOf(p.src_ip);
			s[3] = String.valueOf(p.dst_ip);
			s[4] = "TCP";
			s[5] = ss;
			s[6] = String.valueOf(p.length);			
			System.out.println(str);
		}
		//UDP��
		else if(packet instanceof jpcap.packet.UDPPacket){
			UDPPacket p=(UDPPacket)packet; 
			s[0] = String.valueOf(count);
		//	s[1] = String.valueOf(df.format(System.currentTimeMillis()));
			s[2] = String.valueOf(p.src_ip);
			s[3] = String.valueOf(p.dst_ip);
			s[4] = "UDP";
			//s[5] = String.valueOf(p.data);	
			ss = new String(p.data,"UTF-8");
			s[5] = ss;
			s[6] = String.valueOf(p.length);
		}
		//ICMP��
		else if(packet instanceof jpcap.packet.ICMPPacket){
			ICMPPacket p=(ICMPPacket)packet; 
			s[0] = String.valueOf(count);
			s[1] = "";//String.valueOf(df.format(System.currentTimeMillis()));
			s[2] = String.valueOf(p.src_ip);
			s[3] = String.valueOf(p.dst_ip);
			s[4] = "ICMP";
			s[5] = String.valueOf(p.code);	
			s[6] = String.valueOf(p.length);
		}
		//ARP��
		else if(packet instanceof jpcap.packet.ARPPacket){
			ARPPacket p=(ARPPacket)packet;
			s[0] = String.valueOf(count);
		//	s[1] = String.valueOf(df.format(System.currentTimeMillis()));
			s[2] = String.valueOf(p.getSenderHardwareAddress());
			s[3] = String.valueOf(p.getTargetHardwareAddress());
			s[4] = "ARP";
			s[5] = " ";		
			s[6] = String.valueOf(p.len);
	    }else{
	    	//s[0] = String.valueOf(count);
			count--;
	    }
		count++;
		return s;//����е�����		
	}
	
	public String getiphead() throws IOException{
		//IP��ͷ
		Packet packet = getpacket();
		if((packet instanceof jpcap.packet.IPPacket)){
		    IPPacket ipp = (IPPacket)packet;
		    iphead = "IP��ͷ\n" + "�汾��" + String.valueOf(ipp.version) + "\n" +
		         "ͷ���ȣ� "+String.valueOf(ipp.header.length) + "\n" +
		         "�������ͣ� "+String.valueOf(ipp.header[1]) + "\n" +
		         "�ܳ��ȣ�"+String.valueOf(ipp.len) + "\n" +
		         "��ʶ�� "+String.valueOf(ipp.header[4]) + String.valueOf(ipp.header[5]) + "\n" +
		         "DF��"+String.valueOf(ipp.dont_frag) + "\n" +
		         "MF��"+String.valueOf(ipp.more_frag) + "\n" +
		         "�ֶ�ƫ������ "+String.valueOf(ipp.offset) + "\n" +
		         "�����ڣ� "+String.valueOf(ipp.header[8]) + "\n" +
		         "Э�飺"+String.valueOf(ipp.header[9]) + "\n" +
		         "ͷУ��ͣ� "+String.valueOf(ipp.header[10])+ String.valueOf(ipp.header[11]) + "\n" +
		         "Դ��ַ��"+String.valueOf(ipp.src_ip) + "\n" +
		         "Ŀ�ĵ�ַ��"+String.valueOf(ipp.dst_ip) + "\n" +
		         "ѡ� "+String.valueOf(ipp.option) + "\n\n";
		}
		return iphead;
	}
	
	public String gethead() throws IOException{
		Packet packet = getpacket();
		if(packet instanceof jpcap.packet.TCPPacket){
			TCPPacket p = (TCPPacket)packet;
			subhead = "TCP��ͷ\n"+"Դ�˿ںţ�"+String.valueOf(p.src_port)+"\n"+
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
	          "����ָ�룺"+String.valueOf(p.header[18])+String.valueOf(p.header[19])+"\n"+
	          //"��ѡ�"+String.valueOf(p.option.toString())+"\n"+
	          "��䣺"+String.valueOf(p.header[23]);
		}
		
		if(packet instanceof jpcap.packet.UDPPacket){
			UDPPacket p=(UDPPacket)packet; 
			subhead = "UDP��ͷ\n"+"Դ�˿ڣ�"+ String.valueOf(p.src_port)+"\n"+
			          "Ŀ�Ķ˿ڣ�"+String.valueOf(p.dst_port)+"\n"+
			          "UDP����"+String.valueOf(p.len)+"\n"+
/*У��ͣ�*/	          "UDPУ���"+String.valueOf(p.header[6]+p.header[7]);
		}
		
		if(packet instanceof jpcap.packet.ICMPPacket){
			ICMPPacket p=(ICMPPacket)packet; 
			subhead = "ICMP��ͷ"+"\n"+"���ͣ�"+String.valueOf(p.version)+"\n"+
			          "���룺"+String.valueOf(p.data)+"\n"+
			          "У���"+String.valueOf(p.header[2]+p.header[3]);
		}
		//ARP��
	    if(packet instanceof jpcap.packet.ARPPacket){
			ARPPacket p=(ARPPacket)packet;
			subhead = "ARP��ͷ\n"+"Ӳ�����ͣ�"+String.valueOf(p.hardtype)+"\n"+
			          "Э�����ͣ�"+String.valueOf(p.prototype)+"\n"+
			          "MAC��ַ���ȣ�"+String.valueOf(p.caplen)+"\n"+
			          "Э���ַ���ȣ�"+String.valueOf(p.plen)+"\n"+
			          "�����룺"+String.valueOf(p.operation)+"\n"+
			          "���ͷ�MAC��ַ:"+String.valueOf(p.sender_hardaddr)+"\n"+
			          "���ͷ�IP��ַ:"+String.valueOf(p.sender_protoaddr)+"\n"+
			          "���շ�MAC��ַ:"+String.valueOf(p.target_hardaddr)+"\n"+
			          "���շ�IP��ַ:"+String.valueOf(p.target_protoaddr);
	    }
	    return subhead;
	}
	
}


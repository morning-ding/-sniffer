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
		
		//网卡标签和下拉菜单
		JLabel cardlabel = new JLabel("网卡：");	
		card = new JComboBox(sniffer.getDevice());	
		
		//详细信息和报头
		JLabel infolabel = new JLabel("详细信息：");
		JLabel headlabel = new JLabel("报头：");
		
		//按钮 
		startbutton = new JButton("  开始抓取  ");
		endbutton = new JButton("  结束抓取  ");
		JButton searchbutton = new JButton("数据包查询");
		JButton rebutton = new JButton(" 报文重组   ");
		JButton savebutton = new JButton("   保存txt     ");
		JButton filterbutton = new JButton("  包过滤       ");
				
		//抓到的包
		String[] columnNames = {"序号","时间","源地址","目的地址","协议类型","信息","长度"};
		String[][] tableVales = null;
		tablemodel = new DefaultTableModel(tableVales,columnNames);
		table = new JTable(tablemodel);
		JScrollPane infoscrollPane = new JScrollPane(table);
		
		
		 ///表头宽度设置
		table.getColumnModel().getColumn(0).setPreferredWidth(10);
		table.getColumnModel().getColumn(1).setPreferredWidth(90);
		table.getColumnModel().getColumn(4).setPreferredWidth(40);
		table.getColumnModel().getColumn(5).setPreferredWidth(40);
		table.getColumnModel().getColumn(6).setPreferredWidth(20);
		
		
		//显示详细信息和报头
		final JTextArea text = new JTextArea();
		text.setLineWrap(true); 
		JScrollPane textscrollPane = new JScrollPane(text);
		final JTextArea head = new JTextArea();
		head.setLineWrap(true); 
		JScrollPane headscrollPane = new JScrollPane(head);
		final JTextArea hex = new JTextArea();
		hex.setLineWrap(true); 
		JScrollPane hexscrollPane = new JScrollPane(hex);
		
		
		///鼠标点击的一行的详细信息在文本框输出
		/*有时候点击会显示不出详细信息*/
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

		//布局
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
	
		//监听
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
	
	//点击开始抓取
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

	//点击结束抓取
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
	
	//获取网卡信息
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
	
	//转16进制
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
	
	//得到报头及详细信息
	public String[] getInfo() throws IOException
	{	
		String s[] = new String[7];
		String str[] = new String[2000];//最后改65536成
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Packet packet = getpacket();

		//详细信息输出及16进制
		if(packet != null && packet.data != null){
			infodata[infodatacount] = "信息：" + "\n" + new String(packet.data, "UTF-8");
		//	System.out.println(infodata[infodatacount]);
			infodatacount++;
			hexdata[hexdatacount] = "16进制：\n" + BytesToHexString(packet.data);
	        hexdatacount++;
		}
//		else
//			return null;	
		
        //TCP包 报头及协议分析
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
		//UDP包
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
		//ICMP包
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
		//ARP包
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
		return s;//表格中的数据		
	}
	
	public String getiphead() throws IOException{
		//IP报头
		Packet packet = getpacket();
		if((packet instanceof jpcap.packet.IPPacket)){
		    IPPacket ipp = (IPPacket)packet;
		    iphead = "IP报头\n" + "版本：" + String.valueOf(ipp.version) + "\n" +
		         "头长度： "+String.valueOf(ipp.header.length) + "\n" +
		         "服务类型： "+String.valueOf(ipp.header[1]) + "\n" +
		         "总长度："+String.valueOf(ipp.len) + "\n" +
		         "标识： "+String.valueOf(ipp.header[4]) + String.valueOf(ipp.header[5]) + "\n" +
		         "DF："+String.valueOf(ipp.dont_frag) + "\n" +
		         "MF："+String.valueOf(ipp.more_frag) + "\n" +
		         "分段偏移量： "+String.valueOf(ipp.offset) + "\n" +
		         "生存期： "+String.valueOf(ipp.header[8]) + "\n" +
		         "协议："+String.valueOf(ipp.header[9]) + "\n" +
		         "头校验和： "+String.valueOf(ipp.header[10])+ String.valueOf(ipp.header[11]) + "\n" +
		         "源地址："+String.valueOf(ipp.src_ip) + "\n" +
		         "目的地址："+String.valueOf(ipp.dst_ip) + "\n" +
		         "选项： "+String.valueOf(ipp.option) + "\n\n";
		}
		return iphead;
	}
	
	public String gethead() throws IOException{
		Packet packet = getpacket();
		if(packet instanceof jpcap.packet.TCPPacket){
			TCPPacket p = (TCPPacket)packet;
			subhead = "TCP报头\n"+"源端口号："+String.valueOf(p.src_port)+"\n"+
	          "目的端口号："+String.valueOf(p.dst_port)+"\n"+
	          "发送序号："+String.valueOf(p.sequence)+"\n"+
	          "确认序号："+String.valueOf(p.ack_num)+"\n"+
	          "头部长度："+String.valueOf(p.header.length)+"\n"+
	          "URG："+String.valueOf(p.urg)+"\n"+
	          "ACK："+String.valueOf(p.ack)+"\n"+
	          "PSH："+String.valueOf(p.psh)+"\n"+
	          "RST："+String.valueOf(p.rst)+"\n"+
	          "SYN："+String.valueOf(p.syn)+"\n"+
	          "FIN："+String.valueOf(p.syn)+"\n"+
	          "窗口："+String.valueOf(p.window)+"\n"+
	          "校验和："+String.valueOf(p.header[16])+String.valueOf(p.header[17])+"\n"+
	          "紧急指针："+String.valueOf(p.header[18])+String.valueOf(p.header[19])+"\n"+
	          //"任选项："+String.valueOf(p.option.toString())+"\n"+
	          "填充："+String.valueOf(p.header[23]);
		}
		
		if(packet instanceof jpcap.packet.UDPPacket){
			UDPPacket p=(UDPPacket)packet; 
			subhead = "UDP报头\n"+"源端口："+ String.valueOf(p.src_port)+"\n"+
			          "目的端口："+String.valueOf(p.dst_port)+"\n"+
			          "UDP长度"+String.valueOf(p.len)+"\n"+
/*校验和！*/	          "UDP校验和"+String.valueOf(p.header[6]+p.header[7]);
		}
		
		if(packet instanceof jpcap.packet.ICMPPacket){
			ICMPPacket p=(ICMPPacket)packet; 
			subhead = "ICMP报头"+"\n"+"类型："+String.valueOf(p.version)+"\n"+
			          "代码："+String.valueOf(p.data)+"\n"+
			          "校验和"+String.valueOf(p.header[2]+p.header[3]);
		}
		//ARP包
	    if(packet instanceof jpcap.packet.ARPPacket){
			ARPPacket p=(ARPPacket)packet;
			subhead = "ARP报头\n"+"硬件类型："+String.valueOf(p.hardtype)+"\n"+
			          "协议类型："+String.valueOf(p.prototype)+"\n"+
			          "MAC地址长度："+String.valueOf(p.caplen)+"\n"+
			          "协议地址长度："+String.valueOf(p.plen)+"\n"+
			          "操作码："+String.valueOf(p.operation)+"\n"+
			          "发送方MAC地址:"+String.valueOf(p.sender_hardaddr)+"\n"+
			          "发送方IP地址:"+String.valueOf(p.sender_protoaddr)+"\n"+
			          "接收方MAC地址:"+String.valueOf(p.target_hardaddr)+"\n"+
			          "接收方IP地址:"+String.valueOf(p.target_protoaddr);
	    }
	    return subhead;
	}
	
}


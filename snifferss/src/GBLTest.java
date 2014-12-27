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
		Toolkit kit = Toolkit.getDefaultToolkit(); // 定义工具包 
		Dimension screenSize = kit.getScreenSize(); // 获取屏幕的尺寸 
		int screenWidth = screenSize.width/2; // 获取屏幕的宽
		int screenHeight = screenSize.height/2; // 获取屏幕的高
		int height = this.getHeight();
		int width = this.getWidth(); 
		setLocation(screenWidth-width/2, screenHeight-height/2);
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
		JButton rebutton = new JButton("IP分片重组 ");
		JButton savebutton = new JButton("保存为文件");
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
                head.setText(Sniffer.iphead[detailindex] + Sniffer.subhead[detailindex]);
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
/////			thread.stop();
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
	
	//点击报文重组
	private class RebuttonAction implements ActionListener
	{  
		public void actionPerformed(ActionEvent event)
		{    
			JFrame frame1 = new JFrame("IP分片重组");
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

	//点击保存
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
								    "数据：\n" + Sniffer.infodata[i] + "\n\n");		
						}else if(Sniffer.list.get(i) instanceof jpcap.packet.ARPPacket){
					 	    bw.write(String.valueOf(i) + ":\n" + Sniffer.subhead[i] + 
					 			   "数据：\n" + Sniffer.infodata[i] + "\n\n");	
						}else{
						    bw.write(String.valueOf(i) + ":\n" + "数据：\n" + Sniffer.infodata[i] + "\n\n");	
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
	
	//抓包
	public Packet getpacket() throws IOException{
		JpcapCaptor captor = JpcapCaptor.openDevice(devices[FrontFrame.networkinterfaceNumber], 65535, false, 20);
		Packet packet = captor.getPacket();
		while(packet == null)
			packet = captor.getPacket();
		list.add(packet);
		
		return packet;
	}
	
	//得到报头(调用函数取得)及表格中详细信息
	public String[] getInfo(Packet packet) throws IOException
	{	
		String s[] = new String[7];
	//	String str[] = new String[2000];//最后改65536成
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		gethead(packet);
		getiphead(packet);

		//详细信息输出及16进制
		if(packet != null && packet.data != null){
			infodata[count] = "信息：" + "\n" + new String(packet.data, "UTF-8");
			hexdata[count] = "16进制：\n" + BytesToHexString(packet.data);
		}	
		
        //TCP包 报头及协议分析
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
		//UDP包
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
		//ICMP包
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
		//ARP包
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
	    	s[4] = "其他包";
	    	s[5] = String.valueOf(Arrays.toString(packet.data));	
			s[6] = String.valueOf(packet.len);
	    }
		count++;
		return s;//表格中的数据		
	}
	
	//取得IP报头
	public String getiphead(Packet packet) throws IOException{
		//IP报头
		//Packet packet = getpacket();
		count = list.indexOf(packet);
		if((packet instanceof jpcap.packet.IPPacket)){
		    IPPacket ipp = (IPPacket)packet;
		    iphead[count] = "IP报头\n" + "版本：" + String.valueOf(ipp.version) + "\n" +
		         "头长度： "+String.valueOf(ipp.header.length) + "\n" +
		         "服务类型： "+String.valueOf(ipp.header[1]) + "\n" +
		         "总长度："+String.valueOf(ipp.len) + "\n" +
		         "标识： "+String.valueOf(ipp.ident) + "\n" +
		         "DF："+String.valueOf(ipp.dont_frag) + "\n" +
		         "MF："+String.valueOf(ipp.more_frag) + "\n" +
		         "分段偏移量： "+String.valueOf(ipp.offset) + "\n" +
		         "生存期： "+String.valueOf(ipp.header[8]) + "\n" +
		         "协议："+String.valueOf(ipp.header[9]) + "\n" +
		         "头校验和： "+String.valueOf(ipp.header[10])+ String.valueOf(ipp.header[11]) + "\n" +
		         "源地址："+String.valueOf(ipp.src_ip) + "\n" +
		         "目的地址："+String.valueOf(ipp.dst_ip) + "\n" +
		         "选项： "+String.valueOf(ipp.option) + "\n\n";
		}else{
			iphead[count] = "无ip报头\n\n ";
		}
		return iphead[count];
	}
	
	//取得其他报头
	public String gethead(Packet packet) throws IOException{
	//	Packet packet = getpacket();
		count = list.indexOf(packet);
		if(packet instanceof jpcap.packet.TCPPacket){
			TCPPacket p = (TCPPacket)packet;
			subhead[count] = "TCP报头\n"+"源端口号："+String.valueOf(p.src_port)+"\n"+
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
	          "紧急指针："+String.valueOf(p.urgent_pointer)+"\n"+
	          //"任选项："+String.valueOf(p.option.toString())+"\n"+
	          "填充："+String.valueOf(p.header[23]);
		}
		
		if(packet instanceof jpcap.packet.UDPPacket){
			UDPPacket p=(UDPPacket)packet; 
			subhead[count] = "UDP报头\n"+"源端口："+ String.valueOf(p.src_port)+"\n"+
			          "目的端口："+String.valueOf(p.dst_port)+"\n"+
			          "UDP长度"+String.valueOf(p.len)+"\n"+
/*校验和！*/	          "UDP校验和"+String.valueOf(p.header[6]+p.header[7]);
		}
		
		if(packet instanceof jpcap.packet.ICMPPacket){
			ICMPPacket p=(ICMPPacket)packet; 
			subhead[count] = "ICMP报头"+"\n"+"类型："+String.valueOf(p.version)+"\n"+
			          "代码："+String.valueOf(p.data)+"\n"+
			          "校验和"+String.valueOf(p.header[2]+p.header[3]);
		}
		//ARP包
	    if(packet instanceof jpcap.packet.ARPPacket){
			ARPPacket p=(ARPPacket)packet;
			subhead[count] = "ARP报头\n"+"硬件类型："+String.valueOf(p.hardtype)+"\n"+
			          "协议类型："+String.valueOf(p.prototype)+"\n"+
			          "MAC地址长度："+String.valueOf(p.caplen)+"\n"+
			          "协议地址长度："+String.valueOf(p.plen)+"\n"+
			          "操作码："+String.valueOf(p.operation)+"\n"+
			          "发送方MAC地址:"+String.valueOf(Arrays.toString(p.sender_hardaddr))+"\n"+
			          "发送方IP地址:"+String.valueOf(Arrays.toString(p.sender_protoaddr))+"\n"+
			          "接收方MAC地址:"+String.valueOf(Arrays.toString(p.target_hardaddr))+"\n"+
			          "接收方IP地址:"+String.valueOf(Arrays.toString(p.target_protoaddr));
	    }
	    return subhead[count];
	}
	
	//IP分片重组
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
				flag = true;//需要重组
				c = id[i];//需要重组的标识号
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
				}//reid中存放包的标号
			}
			
		//	int[] re = new int[max];//需要重组的报文的下标且无0
			int[] offset = new int[max];//分段偏移量
			boolean[] mf = new boolean[max];//判断分段是否结束
			String[] data = new String[max];
			for(int i = 0 ; i < max; i++){
				IPPacket ipp = (IPPacket)list.get(reid[i]);
				offset[i] = ipp.offset;
				mf[i] = ipp.more_frag;
				data[i] = Arrays.toString(ipp.data);
			}
			
			//冒泡
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
	        			//如果完整，偏移量的差应相同，都是最大长度。不完整可能出现跳变
	        			    str = "The package is not complete.";
	        			    iscomplete = false;
	        			    break;
	        		    }	        			
	        	    }
	        	    if(offset[max-1] - offset[max-2] > offset[max-2] - offset[max-3]){
	        		//如果完整，最后的偏移量的差必定小于之前的。如果大于，说明之前都是连续的，但是后半部分连续缺少
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


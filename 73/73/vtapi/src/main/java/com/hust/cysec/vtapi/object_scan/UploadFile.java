package com.hust.cysec.vtapi.object_scan;

import java.io.File;
import javax.swing.JFileChooser;
import java.awt.Frame;

import javax.swing.JFrame;

public class UploadFile {
	private JFrame frame;
    
    public UploadFile() {
    	frame = new JFrame();
        frame.setVisible(true);
        bringToFront();
    }
    
    public File getFile() {
    	JFileChooser fc = new JFileChooser();
    	if(JFileChooser.APPROVE_OPTION == fc.showOpenDialog(null)){
    		frame.setVisible(false);
    		return fc.getSelectedFile();
        } else {
        	frame.setVisible(false);
        	return null;
        }
    }

    private void bringToFront() {                  
    	frame.setExtendedState(Frame.ICONIFIED);
    	frame.setExtendedState(Frame.NORMAL);
    }
}

package Malicious;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.stage.DirectoryChooser;

public class Scanner  {
	
	
	
	
	private HashSet<MalwareSignature> Signatures = new HashSet<>();
	HashSet<DetectedMalware> detected = new HashSet<>();
	

    
	
	
	public Scanner(File signatureFile) throws Exception {
		readfile(signatureFile);
	}
	
	public HashSet<DetectedMalware> getDetected(){
		return this.detected;
	}
	
	//file.isDirectory() && includesubfolder
	public int totalfiles(File f , boolean includesubfolder) {
		int count = 0;
		for(File file : f.listFiles()) {
			if((file.isDirectory() && includesubfolder) || (file.isDirectory() && !includesubfolder)) {
				count += totalfiles(file,includesubfolder);
			}
			else if (file.isFile() && file.isHidden() == false && file.canExecute() == true && file.canRead() == true && file.canWrite() == true) {
				count++;
			}
		}
		return count;
	}
	
	
	public void scan(String Path, boolean includesubfolder, ProgressBar progressbar,Label text,BorderPane layout) {
		
		
		try {
			
			
			
			Task<Void> scanTask = new Task<>() {
				
				
				MessageDigest md5 = MessageDigest.getInstance("MD5");
				int totalfiles = totalfiles(new File(Path),includesubfolder);
				AtomicInteger scannedfile = new AtomicInteger();
				
                @Override
                protected Void call() {
                    scanFolder(new File(Path), detected, md5, true, totalfiles, scannedfile);
                    return null;
                }

                private void scanFolder(File folder, HashSet<DetectedMalware> detected, MessageDigest md5, boolean includeSubfolders, int totalFiles, AtomicInteger scannedFiles) {
                    for (File file : folder.listFiles()) {
                        if ((file.isDirectory() && includeSubfolders) || (file.isDirectory() && !includeSubfolders)) {
                            scanFolder(file, detected, md5, includeSubfolders, totalFiles, scannedFiles);
                        }else if (file.isFile() && !file.isHidden() && file.canExecute() && file.canRead() && file.canWrite()) {
                            try {
                            	
                                String hash = MalwareSignature.checksum(md5, file);
                                
                                Signatures.stream()
                                    .filter(sig -> sig.getHash().equals(hash))
                                    .findFirst()
                                    .ifPresent(sig -> detected.add(new DetectedMalware(file.getAbsolutePath(), file.getName(), sig, LocalDate.now().toString())));

                                // Update progress
                                int currentCount = scannedFiles.incrementAndGet();
                                //Method already exsits
                                updateProgress(currentCount, totalFiles);

                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            };

            // Bind progress bar to task progress
            progressbar.progressProperty().bind(scanTask.progressProperty());
            text.textProperty().bind(scanTask.progressProperty().multiply(100).asString("\t\t\tScanning in progress: %.2f%%"));
            
           
            scanTask.setOnSucceeded(e -> {
            	
            	 HashSet<DetectedMalware> detected = getDetected();
            	 if(detected.size() == 0) {
            		
     				Text printable = new Text("There are no malware");
     				Button close = new Button("Close");
     				
     				close.setOnAction(event -> {
     					Text welcome = new Text("Welcome to CPCS 405 Malware Scanner!");
     					((Pane) close.getParent()).getChildren().remove(close);
     					layout.setCenter(welcome);
     					
     			        
     				});
     				
     				
     				
     				TextFlow textArea = new TextFlow(printable);
     		        textArea.setPrefHeight(150); // Adjust height as needed
     		        textArea.setStyle("-fx-border-color: blue; -fx-border-width: 0.5px; -fx-background-color: white;");
     		        textArea.setTextAlignment(javafx.scene.text.TextAlignment.CENTER);
     		        StackPane sp = new StackPane(textArea);
     		       
     		       
     				
     				
     				HBox buttonclosebox = new HBox();
     				buttonclosebox.setAlignment(Pos.CENTER);
     				buttonclosebox.setPadding(new Insets(20, 0, 20 , 0));
     				buttonclosebox.getChildren().add(close);
     				
     				
     				
     				
     				layout.setCenter(sp);
     				layout.setBottom(buttonclosebox);
     				
       
            	 }else if(detected.size() > 0){
            		 detectResult(detected ,layout);
            	 }
            	
            });
            

            Thread t = new Thread(scanTask);
            t.setPriority(Thread.MAX_PRIORITY);;
            t.start();
            
            
      
           
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }
		
		
		
	}

	
	public static void detectResult(HashSet<DetectedMalware> detected ,BorderPane layout) {
		StringBuilder printdetect = new StringBuilder();
		
		detected.forEach(d -> printdetect.append(d.getFilePath())
				.append(" with checksum ")
				.append("\"" + d.getSignature().getHash() + "\"")
				.append(" matches MD5 of ")
				.append("\"" + d.getSignature().getName()+ "\""));
		
		   //----------------------------TEXT----------
			TextFlow textArea = new TextFlow(
				new Text(printdetect.toString())
			);
	        textArea.setPrefHeight(150); // Adjust height as needed
	        textArea.setStyle("-fx-border-color: blue; -fx-border-width: 0.5px; -fx-background-color: white;");
	        //--------------------------------------Button-----------------------------
	        
	        
			
				
			Button delete = new Button("Delete All Files");
			delete.setOnAction(event-> {
				detected.forEach(d -> new File(d.getFilePath()).delete());
				Alert("Done","all files have been successfully deleted");
				
			});
			
			
			
			Button save = new Button("Save");
			save.setOnAction(event->{
				try {
					DirectoryChooser selectDir = new DirectoryChooser();
					selectDir.setTitle("Select the folder want to save");
					File selectedDirectory = selectDir.showDialog(null);
				
					if(selectedDirectory.isDirectory() && selectedDirectory != null) {
        			
						File file = new File(selectedDirectory , "DetectedMalware.ser");
						FileOutputStream FOS = new FileOutputStream(file);
						ObjectOutputStream OOS = new ObjectOutputStream(FOS);
						OOS.writeObject(detected);
						OOS.close();
						Alert("Success", "File saved at: " + file.getAbsolutePath());
        			
        	
        			}
        			
        		}catch(NullPointerException e) {
					Alert("Error" , "Select the folder");
				} catch (FileNotFoundException e) {
					Alert("Error" , "Select the folder");
				} catch (IOException e) {
					Alert("Error" , "Select the folder");
				}
				
        		
				
			});
			
			
			Button close = new Button("Close");
			close.setOnAction(event -> {
				    Text welcome = new Text("Welcome to CPCS 405 Malware Scanner!");
					((Pane) close.getParent()).getChildren().removeAll(close ,delete, save);
					layout.setCenter(welcome);
			});
			
			
	        HBox buttons = new HBox();
	        buttons.getChildren().addAll(save,delete,close);
	        buttons.setAlignment(Pos.CENTER);
	        buttons.setPadding(new Insets(13,0,13,0));
	        HBox.setMargin(delete, new Insets(0, 35, 0, 20));
	        layout.setCenter(textArea);
	        layout.setBottom(buttons);
	}
	
	private static void Alert(String title ,String message) {
		
		Alert s = new Alert(Alert.AlertType.INFORMATION);
		s.setTitle(title);
		s.setContentText(message);
		s.setHeaderText(null);
		s.showAndWait();
		
	}
		

	
	private void readfile(File file) throws Exception{
		
			Files.lines(file.toPath()).forEach(e -> {
				String[] NH = e.split(" ");
				Signatures.add(new MalwareSignature(NH[1],NH[0]));
			});
		
	}
	
	
	

}

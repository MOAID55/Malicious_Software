package Malicious;



import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.util.HashSet;
import javafx.scene.control.Alert;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Text;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MaliciouSoftware extends Application {
	

		private boolean includesubfolder;
		private File selectedDirectory;
		private File selectedfile;
		



		@Override
	    public void start(Stage stage) throws Exception {
			
			
	        BorderPane layout = new BorderPane();
	        MenuBar menubar = new MenuBar();
	        Menu file = new Menu("File");
	        Menu help = new Menu("Help");
	        
	        layout.setTop(menubar);
	        Text welcome = new Text("Welcome to CPCS 405 Malware Scanner!");
	        layout.setCenter(welcome);
	        
	        menubar.setUseSystemMenuBar(true);
	        MenuItem item = new MenuItem("New Scan");
	        MenuItem item2 = new MenuItem("Load");
	        MenuItem item3 = new MenuItem("Quit");
	        MenuItem about = new MenuItem("About");
	        
	       

	        
	        item.setOnAction(event -> {
	        	VBox maincontent = new VBox();
	        	maincontent.setAlignment(Pos.CENTER);
	        	
	        	Label fd1 = new Label("Selcet folder to scan: ");
	        	
	        	//--------------------------------------------------------------------------------------------------------------1
	        	Button bt1 = new Button("Select");
	        	bt1.setOnAction(e -> {
	        		
	        		DirectoryChooser selectDir = new DirectoryChooser();
	        		selectDir.setTitle("Select the folder want to scanned");
	        		selectedDirectory = selectDir.showDialog(stage);
	        		
	        		if(selectedDirectory != null) {
	        			fd1.setText("Selected folder: " + selectedDirectory.getName());
	        		}
	        		
	        	
	                
	        		
	        		
	        	});
	        	
	        	Label fd2 = new Label("Select path of MD5 database: ");
	        	
	        	Button bt2 = new Button("Select");
	        	//--------------------------------------------------------------------------------------------------------------2
	        	bt2.setOnAction(e -> {
	        		
	        		FileChooser selectfile = new FileChooser();
	        		FileChooser.ExtensionFilter filter = new FileChooser.ExtensionFilter("Text Files", "*.txt");
	        		selectfile.getExtensionFilters().add(filter);
	        		selectfile.setTitle("Select file of MD5 database");
	        		
	        		selectedfile = selectfile.showOpenDialog(stage);
	        		
	        		if(selectedfile != null) {
	        			fd2.setText("Selected file : " + selectedfile.getPath());
	        		}
	        		
	        		
	        	});
	        
	        	
	        	CheckBox cb1 = new CheckBox("Include subfolders?");
	        	
	        	cb1.setOnAction(e -> includesubfolder = cb1.isSelected());
	        	
	        	Button StartingScanningButton = new Button("Start Scanning");
	        	
	        	// Create the first HBox with fd1 and bt1, and set margin
	        	HBox s = new HBox(10); // Optional spacing between fd1 and bt1
	        	s.getChildren().addAll(fd1, bt1);
	        	VBox.setMargin(s, new Insets(50,0, 0, 0)); // Margin for HBox within VBox
	        	HBox.setMargin(fd1, new Insets(0,45,0,0));
	        	HBox.setMargin(bt1, new Insets(0,0,0,0));
	        	// Create the second HBox with fd2 and bt2, and set margin
	        	HBox ss = new HBox(10); // Optional spacing between fd2 and bt2
	        	ss.getChildren().addAll(fd2, bt2);
	        	VBox.setMargin(ss, new Insets(50, 0, 70, 0)); // Margin for HBox within VBox

	        	// Set the alignment for each HBox to align content to the 
	        	s.setAlignment(Pos.CENTER_LEFT);
	        	ss.setAlignment(Pos.CENTER_LEFT);

	        	// Add the components to maincontent (assuming maincontent is a VBox)
	        	maincontent.getChildren().addAll(s, ss, cb1, StartingScanningButton);

	        	// Set margin for CheckBox and Button as well
	        	VBox.setMargin(cb1, new Insets(20, 0,50, 0));
	        	VBox.setMargin(StartingScanningButton, new Insets(20, 0, 0, 0));

	        	// Set padding for maincontent and add it to the layout
	        	maincontent.setPadding(new Insets(40));
	        	layout.setCenter(maincontent);
	        	
	        	StartingScanningButton.setOnAction(e -> startScanning(layout));
	       
	        });
	        
	       
	        item2.setOnAction(event -> {
	        	try {
	        		FileChooser selectfile = new FileChooser();
	        		FileChooser.ExtensionFilter filterfileser = new FileChooser.ExtensionFilter("Ser Files", "*.ser");
	        		selectfile.getExtensionFilters().add(filterfileser);
	        		selectfile.setTitle("Select the file you want to deserialize");
	        		File SF = selectfile.showOpenDialog(null);
	        		
	        		if(SF.isFile() && SF != null) {
	        			
	        			FileInputStream FIS = new FileInputStream(SF);
	        			ObjectInputStream OIS = new ObjectInputStream(FIS);
	        			HashSet<DetectedMalware> detected = (HashSet<DetectedMalware>) OIS.readObject();
	        			OIS.close();
	        			Alert("Deserialization Successful" , "The file has been successfully deserialized");
	        			
	        			Scanner.detectResult(detected, layout);
	        		}
	        	}catch(NullPointerException e) {
					Alert("Error" , "Select the file");
				} catch (FileNotFoundException e) {
					Alert("Error" , "Select the file");
				} catch (IOException e) {
					Alert("Error" , "Select the file");
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
	        });
 
	        item3.setOnAction(event -> {
					System.exit(0);
	        });
	        
	        
	        about.setOnAction(event ->{
	        	
	        	Text InformationStudent = new Text("Moaid Ali Alshamrani\n2143005");
	        	layout.setCenter(InformationStudent);
	        	
	        });
	        
	        
	        file.getItems().addAll(item,item2,item3);
	        help.getItems().addAll(about);
	        menubar.getMenus().addAll(file,help);
	        
	        
	        
	        
	        Scene scene = new Scene(layout,500,500);
	        stage.setScene(scene);
	        stage.setTitle("JavaFx");
	        stage.show();
	    }
		
		private void startScanning(BorderPane layout) {
			
			try {
			
				if(selectedDirectory == null || selectedDirectory.getName().equals("")) {
					Alert("Error", "Select Directory first");
					return;
				}
				if(selectedfile == null) {
					Alert("Error" , "Select File text only");
					return;
				}
			
				
			
				Scanner scan = new Scanner(selectedfile);
				
				VBox maincontent = new VBox();
				ProgressBar s = new ProgressBar();
				Label text = new Label("\t\t\tScanning in progress: ");
				
				maincontent.getChildren().addAll(new HBox(7,text,s));
				maincontent.setAlignment(Pos.CENTER);
				layout.setCenter(maincontent);
				
				scan.scan(selectedDirectory.getPath(), includesubfolder,s,text,layout);
				
			}catch(ArrayIndexOutOfBoundsException e) {
				Alert("Error", "Please Enter the right text file that contain database md5");
				return;
			}catch(NullPointerException e) {
				Alert("Error", "Please Enter the folder");
				return;
				
			}catch (Exception e) {
				e.printStackTrace();
			}
			
		
			
		}
		
		
		
		private void Alert(String title ,String message) {
			
			Alert s = new Alert(Alert.AlertType.INFORMATION);
			s.setTitle(title);
			s.setContentText(message);
			s.setHeaderText(null);
			s.showAndWait();
			
		}
		
		
		
		
		
		
		

		
	
	
	public static void main(String[] args) {
        launch(args);
    }

	

    
}

package sample;

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import javafx.fxml.FXML;
import javafx.event.ActionEvent;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Map;

public class Controller {
    public boolean showDebugInfo = true;
    public File fileForScanning;

    @FXML public TextField apikeyTextField1;
    @FXML public TextField scanFilepathTextField1;
    @FXML public Button browseButton1;
    @FXML public Button scanButton;
    @FXML public Label pleaseWaitLabel1;
    @FXML public Stage primaryStage;

    public void ShowError(String title, String message) {
        System.err.println(message);
        Alert alert = new Alert(Alert.AlertType.ERROR, message, ButtonType.OK);
        alert.setTitle("Exception Happened");
        alert.setHeaderText(title);
        alert.showAndWait();
    }

    public void BrowseButton_Click(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select File");
        fileForScanning = fc.showOpenDialog(primaryStage);
        scanFilepathTextField1.setText(fileForScanning.getAbsolutePath());
    }

    public void ScanFile(ActionEvent actionEvent) {
        pleaseWaitLabel1.setVisible(true);
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apikeyTextField1.getText());
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            ScanInfo scanInfo = virusTotalRef.scanFile(fileForScanning);

            System.out.println("***SCANNING INFORMATION***");
            System.out.println("Response Code:\t" + scanInfo.getResponseCode());
            System.out.println("MD5:\t\t\t" + scanInfo.getMd5());
            System.out.println("SHA-1:\t\t\t" + scanInfo.getSha1());
            System.out.println("SHA-256:\t\t" + scanInfo.getSha256());
            System.out.println("Permalink:\t\t" + scanInfo.getPermalink());
            System.out.println("Resource:\t\t" + scanInfo.getResource());
            System.out.println("Scan Date:\t\t" + scanInfo.getScanDate());
            System.out.println("Scan ID:\t\t" + scanInfo.getScanId());
            System.out.println("Verbose Msg:\t" + scanInfo.getVerboseMessage());

            FileScanReport report = virusTotalRef.getScanReport(scanInfo.getResource());

            System.out.println();
            System.out.println("***REPORT***");
            System.out.println("Response Code:\t" + report.getResponseCode());
            System.out.println("Positives:\t\t" + report.getPositives());
            System.out.println("Total:\t\t\t" + report.getTotal());

            boolean infected;
            boolean isDrweb = false;
            String positiveAVs = "";

            Map<String, VirusScanInfo> scans = report.getScans();
            for (String key : scans.keySet()) {
                VirusScanInfo virusInfo = scans.get(key);
                boolean positive = (virusInfo.getResult() != null);
                isDrweb = ((key == "DrWeb") && positive);
                if (positive && positiveAVs != "") { positiveAVs += "," + key; }
                if (positive && positiveAVs == "") { positiveAVs += key; }
                if (showDebugInfo) {
                    System.out.println();
                    System.out.println("Scanner: " + key);
                    System.out.println("\t\t Result:  " + virusInfo.getResult());
                    System.out.println("\t\t Update:  " + virusInfo.getUpdate());
                    System.out.println("\t\t Version: " + virusInfo.getVersion());
                }
            }

            infected = ((report.getPositives() > 5) && isDrweb);
            Alert alert = new Alert(Alert.AlertType.INFORMATION,
                          ((infected) ? "It may be a virus!\n" : "File is clean.\n") + "\n" +
                                    "Positive AVs: " + positiveAVs + "." + "\n" +
                                    report.getPositives() + "/" + report.getTotal(),
                                    ButtonType.OK);
            alert.setTitle("Report about this file");
            alert.setHeaderText((infected ? "Infected!" : "Clean!"));
            alert.showAndWait();
        }
        catch (APIKeyNotFoundException ex) {
            ShowError("APIKeyNotFound Error", "API Key Not Found! " + String.valueOf(ex));
        }
        catch (java.io.UnsupportedEncodingException ex) {
            ShowError("UnsupportedEncoding Error", "Unsupported Encoding! " + String.valueOf(ex));
        }
        catch (FileNotFoundException ex) {
            ShowError("FileNotFound Error", "File Not Found! " + String.valueOf(ex));
        }
        catch (UnauthorizedAccessException ex) {
            ShowError("UnauthorizedAccessException Error", "Invalid API Key! " +
                                                                        String.valueOf(ex));
        }
        catch (Exception ex) {
            System.err.println("Error! " + String.valueOf(ex));
            ShowError("Error", "Error! " + String.valueOf(ex));
        }
        finally {
            System.out.println("Done!");
            System.out.println();
        }
        pleaseWaitLabel1.setVisible(false);
    }
}

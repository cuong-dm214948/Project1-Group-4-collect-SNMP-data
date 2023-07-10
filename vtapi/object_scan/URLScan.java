package com.hust.cysec.vtapi.object_scan;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.util.CellUtil;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class URLScan extends Scan {

	private static final String ERR = "ERROR: ";
	private static final String X_API_KEY = "x-apikey";
	private static final String ERR_ATTR = "error";
	private static final String ERR_MESS = "message";
	private static final String GET_ATTR = "attributes";
	private static final String LAST_STATS = "last_analysis_stats";
	private static final String HARM = "harmless";
	private static final String MAL = "malicious";
	private static final String ENGINE = "engine_name";
	
	//post URL
	@Override
	public void post(String apikey) throws IOException, InterruptedException {
		HttpClient client = HttpClient.newBuilder().build();
		
		String urlElement = "url=" + getName();
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/urls"))
			    .header("accept", "application/json")
			    .header(X_API_KEY, apikey)
			    .header("content-type", "application/x-www-form-urlencoded")
			    .method("POST", HttpRequest.BodyPublishers.ofString(urlElement))
			    .build();
		
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
		try {
			String id = json.getJSONObject("data").getString("id");
			setAnalysisId(id);
			setObjectId(id.split("-")[1]);
		} catch (Exception e) {
			try {
				if (json.getJSONObject(ERR_ATTR).getString("code").equals("InvalidArgumentError"))
					System.out.println("ERROR: Invalid URL!\n");
				else
					System.out.println(ERR + json.getJSONObject(ERR_ATTR).getString(ERR_MESS) + " (" + json.getJSONObject(ERR_ATTR).getString("code") + ")\n");
			} catch (Exception ee) {
				System.out.println(ERR + e.getMessage());
			}
	    }
	}
	

	@Override
	public void getReport(String apikey) throws IOException, InterruptedException {
		if (getObjectId() == null)
			return;
		
		//SEND REANALYSE req if already get report before
		if (getJson() != null) { 
			HttpRequest rescan = HttpRequest.newBuilder()
				    .uri(URI.create("https://www.virustotal.com/api/v3/urls/" + getObjectId() + "/analyse"))
				    .header("accept", "application/json")
				    .header(X_API_KEY, apikey)
				    .method("POST", HttpRequest.BodyPublishers.noBody())
				    .build();
				HttpResponse<String> resp = HttpClient.newHttpClient().send(rescan, HttpResponse.BodyHandlers.ofString());
				JSONObject temp = new JSONObject(resp.body());
			try {
		        this.setAnalysisId(temp.getJSONObject("data").getString("id"));
			} catch (Exception e) {
				try {
			        System.out.println(ERR + temp.getJSONObject(ERR_ATTR).getString(ERR_MESS) + " (" + temp.getJSONObject(ERR_ATTR).getString("code") + ")");
				} catch (Exception ee) {
					System.out.println(ERR + e.getMessage());
				}
		    }
		}
		
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/urls/" + getObjectId()))
			    .header("accept", "application/json")
			    .header(X_API_KEY, apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
		setJson(json);
		//set attributes
		try {
			//GET BASIC INFO
			setName(json.getJSONObject("data").getJSONObject(GET_ATTR).getString("url"));
			
			//GET ANALYSIS
			setTime(json.getJSONObject("data").getJSONObject(GET_ATTR).getInt("last_analysis_date"));
			setHarmless(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt(HARM));
			setUndetected(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt("undetected"));
			setMalicious(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt(MAL));
			setSuspicious(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt("suspicious"));
			setTimeout(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt("timeout"));
		} catch (Exception e) {
			try {
				//check if analysis not finished
				if (json.getJSONObject(ERR_ATTR).getString("code").equals("NotFoundError"))
					System.out.println("WARNING: No finished analysis found!");
				else
					System.out.println(ERR + json.getJSONObject(ERR_ATTR).getString(ERR_MESS) + " (" + json.getJSONObject(ERR_ATTR).getString("code") + ")");
			} catch (Exception ee) {
				//check if analysis not finished
				if (e.getMessage().equals("JSONObject[\"last_analysis_date\"] not found."))
					System.out.println("WARNING: No finished analysis found!");
				else
					System.out.println(ERR + e.getMessage());
			}
	    }	
	}
	
	@Override
	public void writeExcel(XSSFSheet sheet) {
		if (sheet == null) {
			System.out.println("ERROR: Can't write anything.");
			return;
		}
		
	//WRITE BASIC INFO
		Row row = sheet.getRow(1);
        CellUtil.getCell(row, 0).setCellValue("type");
        CellUtil.getCell(row, 1).setCellValue("id");
        CellUtil.getCell(row, 2).setCellValue("name");
        CellUtil.getCell(row, 9).setCellValue("undetected");
        CellUtil.getCell(row, 10).setCellValue(HARM);
        CellUtil.getCell(row, 11).setCellValue("suspicious");
        CellUtil.getCell(row, 12).setCellValue(MAL);
        CellUtil.getCell(row, 13).setCellValue("timeout");
        CellUtil.getCell(row, 15).setCellValue("last_analysis_date");
        
        row = sheet.getRow(2);
        CellUtil.getCell(row, 0).setCellValue("url");
        CellUtil.getCell(row, 1).setCellValue(getObjectId());
        CellUtil.getCell(row, 2).setCellValue(getName());
        CellUtil.getCell(row, 9).setCellValue(getUndetected());
        CellUtil.getCell(row, 10).setCellValue(getHarmless());
        CellUtil.getCell(row, 11).setCellValue(getSuspicious());
        CellUtil.getCell(row, 12).setCellValue(getMalicious());
        CellUtil.getCell(row, 13).setCellValue(getTimeout());
        CellUtil.getCell(row, 15).setCellValue(getTime());
        
   //WRITE ANALYSIS RESULTS
        row = sheet.getRow(1);
        CellUtil.getCell(row, 16).setCellValue(ENGINE);
        CellUtil.getCell(row, 17).setCellValue("category");
        CellUtil.getCell(row, 18).setCellValue("result");
        
        List<JSONObject> engines = new ArrayList<>();
        JSONObject json = getJson().getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject("last_analysis_results");
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            JSONObject nestedJsonObject = json.getJSONObject(keys.next());
            engines.add(nestedJsonObject);
        }
		Collections.sort(engines, (j1, j2) -> {
			String name1 = (String) j1.get(ENGINE);
			String name2 = (String) j2.get(ENGINE);
			return name1.compareToIgnoreCase(name2);
		});

		int iRow = 2;
        for (JSONObject engine: engines) {
        	row = sheet.getRow(iRow);
        	if (row == null)
        		row = sheet.createRow(iRow);
        	CellUtil.getCell(row, 16).setCellValue(engine.getString(ENGINE));
            CellUtil.getCell(row, 17).setCellValue(engine.getString("category"));
            if (!engine.isNull("result")) {
            	CellUtil.getCell(row, 18).setCellValue(engine.getString("result"));
            }
        	iRow++;
        }
        if (iRow < 101) {
        	row = sheet.getRow(101);
        	CellUtil.getCell(row, 16).setBlank();
        }
        
    // WRITE OTHER URL INFOS
        row = sheet.getRow(1);
        CellUtil.getCell(row, 3).setCellValue("first_submission_date");
        CellUtil.getCell(row, 4).setCellValue("last_submission_date");
        CellUtil.getCell(row, 5).setCellValue("last_final_url");
        CellUtil.getCell(row, 8).setCellValue("threat_names");
        CellUtil.getCell(row, 19).setCellValue("reputation");
        CellUtil.getCell(row, 20).setCellValue(HARM);
        CellUtil.getCell(row, 21).setCellValue(MAL);
        
        json = getJson().getJSONObject("data").getJSONObject(GET_ATTR);
        row = sheet.getRow(2);
        CellUtil.getCell(row, 3).setCellValue(json.getLong("first_submission_date"));
        CellUtil.getCell(row, 4).setCellValue(json.getLong("last_submission_date"));
        CellUtil.getCell(row, 5).setCellValue(json.getString("last_final_url"));
        CellUtil.getCell(row, 19).setCellValue(json.getInt("reputation"));
        CellUtil.getCell(row, 20).setCellValue(json.getJSONObject("total_votes").getInt(HARM));
        CellUtil.getCell(row, 21).setCellValue(json.getJSONObject("total_votes").getInt(MAL));
        //Write URL threat names
        JSONArray names = json.getJSONArray("threat_names");
        iRow = 2;
        for (int i = 0; i < names.length(); i++) {
        	row = sheet.getRow(iRow);
        	CellUtil.getCell(row, 8).setCellValue(names.getString(i));
        	iRow++;
        }
    
    // WRITE CATEGORIES
        row = sheet.getRow(1);
        CellUtil.getCell(row, 6).setCellValue("categorizers");
        CellUtil.getCell(row, 7).setCellValue("categories");
        
        json = getJson().getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject("categories");
        keys = json.keys();
        iRow = 2;
        while (keys.hasNext()) {
            String key = keys.next();
            row = sheet.getRow(iRow);
        	if (row == null)
        		row = sheet.createRow(iRow);
        	CellUtil.getCell(row, 6).setCellValue(key);
            CellUtil.getCell(row, 7).setCellValue(json.getString(key));
        	iRow++;
        }
	}
}

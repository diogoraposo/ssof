package braindeadanalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map.Entry;
import java.util.TreeMap;

public class Analyzer {

	public static void main(String[] args) {
		
		boolean DEBUG = true;
		
		//File patternsfile = new File(System.getProperty("user.dir") + "/src/braindeadanalyzer/patterns");
		File patternsfile = new File(System.getProperty("user.dir") + "/../src/braindeadanalyzer/patterns");
		TreeMap<String, Vulnerability> vulns = new TreeMap<String, Vulnerability>();
		ArrayList<String> dataFlow = new ArrayList<String>();
		
		//Read patterns file
		try (BufferedReader br = new BufferedReader(new FileReader(patternsfile))) {
		    String line;
		    while ((line = br.readLine()) != null) {
		    	Vulnerability vuln = new Vulnerability(line);
		    	line = br.readLine();
		    	String[] eps = line.split(",");
		    	for(String s: eps){
		    		vuln.addEntryPoint(s);
		    	}
		    	line = br.readLine();
		    	String[] funcs = line.split(",");
		    	for(String s: funcs){
		    		vuln.addSanitFunction(s);
		    	}
		    	line = br.readLine();
		    	String[] sanits = line.split(",");
		    	for(String s: sanits){
		    		vuln.addSensitiveSink(s);
		    	}
		    	line=br.readLine();
		    	vulns.put(vuln.get_description(), vuln);
		    	if(DEBUG) System.out.println(vuln.toString());
		    }
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String phpfile = args[0];
		File phpFile = new File(System.getProperty("user.dir") + phpfile);
		
		try (BufferedReader br = new BufferedReader(new FileReader(phpFile))) {
			String line;
		    while ((line = br.readLine()) != null) {
		    	if(line.contains("=")){
		    		for(String s: dataFlow){
		    			if(line.split("=")[1].contains(s)){
		    				String tmp = line.split("=")[0].trim();
		    				if(!dataFlow.contains(tmp)){
		    					dataFlow.add(tmp);
		    				}
		    			}
		    		}
		    	}
		    	for(Entry<String, Vulnerability> v : vulns.entrySet()){
		    		for(String s: v.getValue().get_entryPoints()){
		    			if(line.contains(s)){
		    				v.getValue().set_active(true);
		    				String[] members = line.split("=");
		    				if(members.length > 1){
		    					String entryPoint = members[0];
		    					//if(DEBUG) System.out.println("Entry point is: " + entryPoint);
		    					//entryPoint = entryPoint.replaceAll("\t", "");
		    					//entryPoint = entryPoint.replaceAll(" ", "");
		    					entryPoint = entryPoint.trim();
		    					//if(DEBUG) System.out.println("Entry point is now: " + entryPoint);
		    					if(!dataFlow.contains(entryPoint) && entryPoint.length()>0)
		    						dataFlow.add(entryPoint);
		    				}
		    			}
		    		}
		    		for(String s: v.getValue().get_sanitFunctions()){
		    			if(line.contains(s)){
		    				v.getValue().set_secure(true);
		    			}
		    		}
		    		for(String s: v.getValue().get_sensitiveSinks()){
		    			for(String ss: dataFlow){
							if (line.contains(" " + s + " ") && line.contains(ss)) {
								if (v.getValue().is_active()
										&& !v.getValue().is_secure()) {
									System.out
											.println("The line: \""
													+ line
													+ "\" is NOT SECURE on the sink -"
													+ s
													+ "- for the type of vulnerability: "
													+ v.getKey().toString()
													+ " on file: " + phpFile);
									System.out.println("");
									System.out.println("");
									System.out
											.println("---------------------------------------------------------");
								}
							}
		    			}
		    		}
		    	}
		    }
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if(DEBUG) for(String ss: dataFlow) System.out.println("Entry point variable: " + ss);
	}

}

/*
Copyright 2015 Inferapp

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.inferapp;

import java.util.*;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.collect.HashMultimap;
import com.google.common.base.Stopwatch;
import com.google.common.io.Files;

/**
 * The <code>DiscoverySource</code> class represents either addremove, file or pkginst discovery source.
 * @author Inferapp
 * @version 1.0
 */
class DiscoverySource
{
	/** 0: file, 1: addremove, 2: pkginst */
	int sourceTypeID;

	/** File name, addremove description, or pkginst name.*/
	String sourceKeyOriginal;
	/** File name, addremove description, or pkginst name. Uppercased for key usage.*/
	String sourceKeyUpperCase;
	
	String sourceProductVersion;
	String sourceCompanyName;
	String sourceProductName;
	String sourceFileDescription;
	String sourceFileVersion;
	String sourceFileSize;
	String sourceFilePath;	
	//String sourceInstalledLocation;
	//String sourceUninstallString;
	//String sourceOSComponent;
	String sourceScanPath;
}

/**
 * The <code>DiscoveryRule</code> class represents either addremove, file or pkginst discovery rule.
 * @author Inferapp
 * @version 1.0
 */
class DiscoveryRule
{	
	int versionID;
	int buildID;
	
	/** 0: Autonumber.*/
	int ruleID;
	
	/** 0: file, 1: addremove, 2: pkginst */
	int sourceTypeID;
	
	/** File name, addremove description, or pkginst name. Uppercased for key usage.*/
	String ruleKeyUpperCase;
	/** File name, addremove description, or pkginst name.*/
	String ruleKeyOriginal;
	
	/** Simple glob style wildcard allowed, replaced with .* for regex matching.*/
	String ruleProductVersion; 
	boolean isRuleProductVersionRegex;
	
	/** Simple glob style wildcard allowed, replaced with .* and preappended with (?i) for case insensitive regex matching.*/
	String ruleProductName;
	boolean isRuleProductNameRegex;
	
	/** Simple glob style wildcard allowed, replaced with .* for regex matching.*/
	String ruleFileVersion;
	boolean isRuleFileVersionRegex;
	
	String ruleFileSize;
	
	/** 
	 * Simple glob style wildcard allowed, replaced with .* and preappended with (?i) for case insensitive regex matching.
	 * Always a regex whenever nonempty so no need for a separate boolean.
	 */
	String ruleFilePath;
}

/**
 * The <code>DiscoveryRules</code> container provides lookups of discovery rules by
 * sourceTypeID/ruleKeyUpperCase and sourceTypeID/ruleKeyUpperCase/ruleProductVersion,
 * as well as a lookup to get the count of rules for a given buildID.
 * @author Inferapp
 * @version 1.0
 */
class DiscoveryRules
{
	/** Index on sourceTypeID, ruleKeyUpperCase and ruleProductVersion, non-unique, hence HashMultimap necessary.*/
	private HashMultimap<String, DiscoveryRule> discoveryRulesBySourceTypeIDRuleKeyRuleProductVersion = HashMultimap.create();
	
	/** Index on sourceTypeID and ruleKeyUpperCase, non-unique, hence HashMultimap necessary.*/
	private HashMultimap<String, DiscoveryRule> discoveryRulesBySourceTypeIDRuleKey = HashMultimap.create();
	
	/** 
	 * Lookup map to get the count of rules for a given buildID.
	 * In C++ version there is an index on buildID for some other purposes (patterns) in this container type
	 * so we can get the count of buildID on that instead, which is not that inefficient because most buildIDs have just one rule.
	 */
	private HashMap<Integer, Integer> discoveryRulesBuildIDCount = new HashMap<>();
	
	public void put(DiscoveryRule rule)
	{
		discoveryRulesBySourceTypeIDRuleKeyRuleProductVersion.put(rule.sourceTypeID + rule.ruleKeyUpperCase + rule.ruleProductVersion, rule);
		
		discoveryRulesBySourceTypeIDRuleKey.put(rule.sourceTypeID + rule.ruleKeyUpperCase, rule);
		
		Integer ruleCount = discoveryRulesBuildIDCount.get(rule.buildID);
		if (ruleCount == null)
			discoveryRulesBuildIDCount.put(rule.buildID, 1);
		else
			discoveryRulesBuildIDCount.put(rule.buildID, ++ruleCount);
	}
	
	public int getBuildIDCount(int buildID)
	{
		return discoveryRulesBuildIDCount.get(buildID);
	}
	
	public Set<DiscoveryRule> get(int sourceTypeID, String ruleKeyUpperCase, String ruleProductVersion)
	{
		return discoveryRulesBySourceTypeIDRuleKeyRuleProductVersion.get(sourceTypeID + ruleKeyUpperCase + ruleProductVersion);
	}
	
	public Set<DiscoveryRule> get(int sourceTypeID, String ruleKeyUpperCase)
	{
		return discoveryRulesBySourceTypeIDRuleKey.get(sourceTypeID + ruleKeyUpperCase);
	}
}

/**
 * The <code>DiscoveryMatch</code> class stores a single match between a rule and a source.
 * It also provides a natural order by rule.ruleID.
 * This is required for use in DiscoveryResult, which has a set of DiscoveryMatches,
 * and we only care for the first match against any unique DiscoveryRule,
 * so this natural ordering of DiscoveryMatch by rule.ruleID effectively prevents
 * adding more than one DiscoveryMatch with same DiscoveryRule.ruleID under given DiscoveryResult.
 * @author Inferapp
 * @version 1.0
 */
class DiscoveryMatch implements Comparable<DiscoveryMatch>
{
	DiscoveryRule rule;
	DiscoverySource source;
	
	DiscoveryMatch(DiscoveryRule rule, DiscoverySource source)
	{
		this.rule = rule;
		this.source = source;
	}
	
	/** Natural order by rule.ruleID.*/
	public int compareTo(DiscoveryMatch dm)
	{
		return this.rule.ruleID - dm.rule.ruleID;
	}
}

/**
 * The <code>DiscoveryResult</code> class stores a set of discovery matches for a path/versionID/buildID.
 * It also provides a natural order by path/versionID/buildID, as implemented in its compareTo method.
 * This is required for use in DiscoveryResults, which is an ordered set of discovery results.
 * @author Inferapp
 * @version 1.0
 */
class DiscoveryResult implements Comparable<DiscoveryResult>
{
	String path;
	int versionID;
	int buildID;
	TreeSet<DiscoveryMatch> discoveryMatches = new TreeSet<DiscoveryMatch>();
	
	DiscoveryResult(String path, int versionID, int buildID)
	{
		this.path = path;
		this.versionID = versionID;
		this.buildID = buildID;
	}
	
	/** Natural order by path/versionID/buildID.*/
	public int compareTo(DiscoveryResult rule)
	{
		if (!path.equals(rule.path))
			return path.compareTo(rule.path);
		if (versionID != rule.versionID)
			return versionID - rule.versionID;
		return buildID - rule.buildID;
	}
}

/**
 * The <code>DiscoveryResults</code> container is a set ordered by path/versionID/buildID,
 * which provides the required iteration capability by path natural order.
 * It also facilitates searches for path/versionID/buildID (unique) and path/versionID (non-unique).
 * @author Inferapp
 * @version 1.0
 */
@SuppressWarnings("serial")
// The lookups could be implemented as nested HashMap and HashMultiMap accordingly,
// if not for the fact that we also remove items from this container,
// so the whole structure would likely get more complex than it's worth,
// not to mention the overhead of maintaining three containers in sync,
// especially that this container never has more than like 100-300 discovery results
// as it is built separately per scan processing task,
// so instead this class offers lookup functionality
// by imitating Boost-like composite index find methods on this ordered set.
class DiscoveryResults extends TreeSet<DiscoveryResult>
{	
	/** This method either gets existing or adds and returns a new DiscoveryResult with supplied path/versionID/buildID.*/
	// It instantiates a new DiscoveryResult with path/versionID/buildID to look for,
	// passes it to the set's ceiling method, and verifies that path/versionID/buildID match.
	// Virtually all calls will return searchResult so the new DiscoveryResult instantiation is almost never wasted.
	public DiscoveryResult getOrAddNew(String path, int versionID, int buildID)
	{
		DiscoveryResult searchResult = new DiscoveryResult(path, versionID, buildID);
		DiscoveryResult existingResult = this.ceiling(searchResult);
		if (existingResult != null && existingResult.path.equals(path) && existingResult.versionID == versionID && existingResult.buildID == buildID)
			return existingResult;
		else
		{
			this.add(searchResult);
			return searchResult;
		}
	}

	/** This method gets existing DiscoveryResult with supplied path/versionID/buildID or returns null.*/
	// Imitate Boost's composite index search on path/versionID/buildID
	// There can be only one such DiscoveryResult.
	// Brute-search for now, as there's never more than like 100-300 discovery results per scan. 
	public DiscoveryResult get(String path, int versionID, int buildID)
	{
		for (DiscoveryResult result : this)
		{
			if (result.path.equals(path) && result.versionID == versionID && result.buildID == buildID)
				return result;
		}
		return null;
	}
	
	/** This method gets the first matching DiscoveryResult with supplied path/versionID or returns null.*/
	// Imitate Boost's composite index _partial_ search on path/versionID.
	// The set is sorted by path/versionID/buildID but
	// there may be many elements with the same path and even the same path/versionID
	// so we only get the first one, which is all we happen to be interested in in our usage of this.
	// Brute-search for now, as there's never more than like 100-300 discovery results per scan. 
	public DiscoveryResult getFirst(String path, int versionID)
	{
		for (DiscoveryResult result : this)
		{
			if (result.path.equals(path) && result.versionID == versionID)
				return result;
		}
		return null;
	}
}

/**
 * The <code>DiscoveryAggregateResult</code> class stores a discovery result by
 * detectionPath/versionID/buildID, with total count and first better scanPath.
 * @author Inferapp
 * @version 1.0
 */
class DiscoveryAggregateResult
{
	String detectionPath;
	int versionID;
	int buildID;
	AtomicInteger count;
	String scanPath;
	DiscoveryAggregateResult(String detectionPath, int versionID, int buildID, int count, String scanPath)
	{
		this.detectionPath = detectionPath;
		this.versionID = versionID;
		this.buildID = buildID;
		this.count = new AtomicInteger(count);
		this.scanPath = scanPath;
	}
}

/**
 * The <code>DiscoverySignature</code> class stores publisher, product and version fields,
 * used for verbose software discovery results.
 * @author Inferapp
 * @version 1.0
 */
class DiscoverySignature
{
	int publisherID;
	String publisherName;
	String webPage;
	int productID;
	String productName;
	String productLicensable;
	String productCategory;
	int versionID;
	String uniqueVersion;
	String build;
	String major;
	String minor;
	String edition;
	String variation;
	String licenseVersion;
}

/**
 * The <code>DiscoveryEngine</code> has a static container for discovery rules
 * as well as static aggregates for sources and results, which are shared by all the tasks,
 * which are instances of its ProcessScanTask nested static class.
 * @author Inferapp
 * @version 1.0
 */
public class DiscoveryEngine
{	
	/** 
	 * discoveryRules stores discovery rules,
	 * shared by all the processing threads (reads only), see the container's class definition for details.
	 */
	private static DiscoveryRules discoveryRules = new DiscoveryRules();
	
	/**
	 * discoveryVERs stores version exclusion rules,
	 * shared by all the processing tasks (reads only).
	 * The key is excludedVersionID, the value is versionID.
	 * The same excludedVersionID may be excluded by many different versionIDs, hence multimap.
	 */
	private static HashMultimap<Integer, Integer> discoveryVERs = HashMultimap.create();
	
	/**
	 * discoverySignatures is a lookup for verbose software discovery results,
	 * shared by all the processing tasks (reads only).
	 * The key is versionID.
	 */
	private static HashMap<Integer, DiscoverySignature> discoverySignatures = new HashMap<>();
	
	/**
	 * discoveryAggregateSources is an aggregate of all unique sources (addremoves/files/pkginsts),
	 * shared by all the processing tasks (lookups and additions).
	 * The key is concatenation of:
	 * for addremoves: sourceKeyUpperCase + sourceProductVersion + sourceCompanyName
	 * for files: sourceKeyUpperCase + sourceProductVersion + sourceCompanyName + sourceProductName
	 * + sourceFileDescription + sourceFileVersion + sourceFileSize
	 */
	private static ConcurrentHashMap<String, DiscoverySource> discoveryAggregateSources = new ConcurrentHashMap<>();
	
	/**
	 * discoveryAggregateResults is an aggregate of all discovery results, unique by detectionPath/versionID/buildID,
	 * shared by all the processing tasks (lookups and additions).
	 * The key is buildID + uppercased detectionPath (no need for versionID because buildID uniquely determines versionID).
	 */
	private static ConcurrentHashMap<String, DiscoveryAggregateResult> discoveryAggregateResults = new ConcurrentHashMap<>();
	
	/**
	 * The <code>ProcessScanTask</code> static class is nested within DiscoveryEngine
	 * so that it has access to its static containers, shared by all the tasks.
	 * @author Inferapp
	 * @version 1.0
	 */
	private static class ProcessScanTask implements Runnable
	{
		/** The scan to be processed by the task.*/
		private String sourceScanPath;
		
		/** Input scan data, i.e. addremoves/files/pkginsts. We just need one simple iteration in any order so ArrayList is sufficient.*/
		private ArrayList<DiscoverySource> discoveryMachineSources = new ArrayList<>();
		
		/** The container to build discovery results for the scan, see the container's class definition for details.*/
		private DiscoveryResults discoveryMachineResults = new DiscoveryResults();
		
		ProcessScanTask(String sourceScanPath)
		{
			this.sourceScanPath = sourceScanPath;
		}
		
		@Override
		public void run()
		{
			try {
				loadScan();			
			}
			catch(IOException ex) {
				System.out.println(ex.toString());
				return;
			}
			
			processScan();

			try {
				saveDiscoveryMachineResults();
			}
			catch(IOException ex) {
				System.out.println(ex.toString());
				return;
			}			
		}
		
		private void loadScan() throws IOException
		{
			BufferedReader bReader = new BufferedReader(
					new FileReader(sourceScanPath));
			String line;
			int mode = -1; // 0 for files, 1 for addremoves			
			
			while ((line = bReader.readLine()) != null)
			{
				if (line.startsWith("<SourceName=AddRemoves>")) {
					mode = 1;
					continue;
				}
				else if (line.startsWith("<SourceName=Files>")) {
					mode = 0;
					continue;
				}
				
				if (mode == 1) {						
					// <Fields=DisplayName		DisplayVersion	Publisher	InstallLocation	sourceUninstallString		SystemComponent>
					String fields[] = line.split("\t", -1);
					
					if (fields.length != 6) {
						System.out.println("In the scan: \n" + sourceScanPath + "\nthe following line is corrupted:");
						for (String field : fields)
							System.out.println(field + "\t");
						System.out.println("\n");
						continue;
					}
					
					DiscoverySource source = new DiscoverySource();
					source.sourceScanPath = sourceScanPath;
					source.sourceTypeID = 1;						
					source.sourceKeyUpperCase = fields[0].toUpperCase();
					source.sourceKeyOriginal = fields[0];
					source.sourceProductVersion = fields[1];
					source.sourceCompanyName = fields[2];
					//source.sourceInstalledLocation = fields[3];
					//source.sourceUninstallString = fields[4];
					//source.sourceOSComponent = fields[5];
					
					// initialize the following to empty string because it is used as key in DiscoveryResults
					// i.e. addremoves are treated as if detected under empty path
					source.sourceFilePath = "";

					String key = source.sourceKeyUpperCase + source.sourceProductVersion + source.sourceCompanyName;
					
					discoveryAggregateSources.putIfAbsent(key, source);
					
					discoveryMachineSources.add(source);
				}
				else if (mode == 0) {
					// <Fields=FilePath	FileName	ProductVersion	CompanyName	ProductName	FileDescription	FileVersion	FileSize>
					String fields[] = line.split("\t", -1);
					
					if (fields.length != 8) {
						System.out.println("In the scan: \n" + sourceScanPath + "\nthe following line is corrupted:");
						for (String field : fields)
							System.out.println(field + "\t");
						System.out.println("\n");
						continue;
					}
					
					DiscoverySource source = new DiscoverySource();;
					source.sourceScanPath = sourceScanPath;
					source.sourceTypeID = 0;
					source.sourceFilePath = fields[0];
					source.sourceKeyUpperCase = fields[1].toUpperCase();
					source.sourceKeyOriginal = fields[1];						
					source.sourceProductVersion = fields[2];
					source.sourceCompanyName = fields[3];
					source.sourceProductName = fields[4];
					source.sourceFileDescription = fields[5];
					source.sourceFileVersion = fields[6];
					source.sourceFileSize = fields[7];
					
					String key = source.sourceKeyUpperCase + source.sourceProductVersion + source.sourceCompanyName + source.sourceProductName 
							+ source.sourceFileDescription + source.sourceFileVersion + source.sourceFileSize;
					
					discoveryAggregateSources.putIfAbsent(key, source);
										
					discoveryMachineSources.add(source);
				}
			}
			bReader.close();
		}
		
		private void processScan() 
		{			
			// build matches between sources and rules
			for (DiscoverySource source : discoveryMachineSources)
			{				
				// find all rules matching the source on sourceTypeID and sourceKeyUpperCase
				for(DiscoveryRule rule : discoveryRules.get(source.sourceTypeID, source.sourceKeyUpperCase))
				{					
					// eliminate rules whose remaining non-empty attributes do not match the source
					if (!rule.ruleProductVersion.isEmpty())
						if(!rule.isRuleProductVersionRegex	&& !source.sourceProductVersion.equals(rule.ruleProductVersion))
							continue;
						else if (rule.isRuleProductVersionRegex && !source.sourceProductVersion.matches(rule.ruleProductVersion))
							continue;

					if (!rule.ruleProductName.isEmpty())
						if(!rule.isRuleProductNameRegex && !source.sourceProductName.equalsIgnoreCase(rule.ruleProductName))
							continue;
						else if(rule.isRuleProductNameRegex && !source.sourceProductName.matches(rule.ruleProductName))
							continue;
					
					if (!rule.ruleFileVersion.isEmpty())
						if(!rule.isRuleFileVersionRegex && !source.sourceFileVersion.equals(rule.ruleFileVersion))
							continue;
						else if(rule.isRuleFileVersionRegex && !source.sourceFileVersion.matches(rule.ruleFileVersion))
							continue;

					if (!rule.ruleFileSize.isEmpty() && !source.sourceFileSize.equals(rule.ruleFileSize))
						continue;
					
					if (!rule.ruleFilePath.isEmpty() && !source.sourceFilePath.matches(rule.ruleFilePath))
						continue;
					
					// if it gets to this point then the rule matches the source on all attributes
					// and we will add a new DiscoveryMatch to discoveryMachineResults
					// for an existing DiscoveryResult with current sourceFilePath, versionID and buildID
					// or to a newly added DiscoveryResult with such attributes if it does not yet exist
					DiscoveryResult result = discoveryMachineResults.getOrAddNew(source.sourceFilePath, rule.versionID, rule.buildID);	
					result.discoveryMatches.add(new DiscoveryMatch(rule, source));
				}
			}
			
			// discovery match multiplication for path based results
			// which allows to combine non-file and file based detection on concrete paths
			// and also multiple files living in the same subtree to trigger the same buildID
			for (Iterator<DiscoveryResult> itPathResult = discoveryMachineResults.iterator(); itPathResult.hasNext();)
			{				
				DiscoveryResult pathResult = itPathResult.next();
				
				// skip all non-path results at the beginning (i.e. pure addremove/pkginst based) 
				// in C++ version we just start from the exclusive end of an equal range
				// for a composite index partial find on empty path instead
				if (pathResult.path.equals(""))
					continue;
				
				// for each path based match, add all matches of the non-path detection result with matching buildID
				// which allows to combine non-file and file based detection on concrete paths
				DiscoveryResult nonPathResult = discoveryMachineResults.get("", pathResult.versionID, pathResult.buildID);	
				if (nonPathResult != null)
					pathResult.discoveryMatches.addAll(nonPathResult.discoveryMatches);
				
				// for each path based match we will add subpath matches provided their buildIDs match
				// which allows multiple files living in the same subtree to trigger the same buildID
				Iterator<DiscoveryResult> itSubPathResult = itPathResult;
				while (itSubPathResult.hasNext())
				{
					DiscoveryResult subPathResult = itSubPathResult.next();
					
					// find first different path
					if (subPathResult.path.equals(pathResult.path))
						continue;
					// if it is different, then check if it is in fact a subpath of path
					else if (subPathResult.path.startsWith(pathResult.path))
					{
						// if yes, check if the buildIDs match
						if (subPathResult.buildID == pathResult.buildID)
						{
							// if yes, add all the subpath matches to those in the path
							pathResult.discoveryMatches.addAll(subPathResult.discoveryMatches);
						}
					}
					// discoveryMachineResults is sorted by path so if it is diferent and not a subpath of path then that's it
					else
						break;
				}
			}

			// prune the discovery results down to those whose matched rule count for given buildID equals discovery rule count for this buildID
			for (Iterator<DiscoveryResult> itResult = discoveryMachineResults.iterator(); itResult.hasNext();)
			{
				DiscoveryResult result = itResult.next();				
				if (result.discoveryMatches.size() != discoveryRules.getBuildIDCount(result.buildID))
					itResult.remove();
			}
			
			// apply version exclusion rules, erase excluded versions
			for (Iterator<DiscoveryResult> itResult = discoveryMachineResults.iterator(); itResult.hasNext();)
			{
				DiscoveryResult result = itResult.next();				
				if (isVersionExcluded(result.path, result.versionID))
					itResult.remove();
			}
			
			// add to global discovered aggregate results
			for (DiscoveryResult result : discoveryMachineResults)
			{
				String key = result.buildID + result.path.toUpperCase();				
				DiscoveryAggregateResult aggregateResult = discoveryAggregateResults.get(key);
				if(aggregateResult != null)
					aggregateResult.count.incrementAndGet();
				else
					discoveryAggregateResults.putIfAbsent(key, 
							new DiscoveryAggregateResult(result.path, result.versionID, result.buildID, 1, sourceScanPath));
			}
		}
		
		// recursive, because a version may be excluded via a chain of version exclusion rules
		private boolean isVersionExcluded(String path, int oldVersionID)
		{
			boolean returnValue = false;
			for(int newVersionID : discoveryVERs.get(oldVersionID))
			{
				if(discoveryMachineResults.getFirst(path, newVersionID) != null)
				{
					returnValue = true;
					break;
				}
				else
					returnValue = isVersionExcluded(path, newVersionID);
			}
			return returnValue;
		}
		
		synchronized private void saveDiscoveryMachineResults() throws IOException
		{			
			BufferedWriter bWriterResults = new BufferedWriter(
					new FileWriter("s:\\results\\results.txt", true));
			BufferedWriter bWriterResultsVerboseAddremoves  = new BufferedWriter(
					new FileWriter("s:\\results\\results_verbose_addremoves.txt", true));
			BufferedWriter bWriterResultsVerboseFiles = new BufferedWriter(
					new FileWriter("s:\\results\\results_verbose_files.txt", true));
			
			for (DiscoveryResult result : discoveryMachineResults)
			{
				bWriterResults.write(result.versionID + "\t" + result.buildID + "\t" + result.path + "\t" + sourceScanPath + "\r\n");
				
				DiscoverySignature signature = discoverySignatures.get(result.versionID);
				if (signature != null)
					for (DiscoveryMatch match : result.discoveryMatches)
					{
						if (match.rule.sourceTypeID == 0)
							bWriterResultsVerboseFiles.write(sourceScanPath + "\t"
									+ signature.publisherID + "\t" + signature.publisherName + "\t" + signature.webPage + "\t"
									+ signature.productID + "\t" + signature.productName + "\t" + signature.productLicensable + "\t"
									+ signature.productCategory + "\t" + signature.versionID + "\t" + signature.uniqueVersion + "\t"
									+ signature.build + "\t" + signature.major + "\t" + signature.minor + "\t"
									+ signature.edition + "\t" + signature.variation + "\t" + signature.licenseVersion + "\t"
									+ "file" + "\t" + match.source.sourceCompanyName + "\t"
									+ match.source.sourceKeyOriginal + "\t" + match.source.sourceFileDescription + "\t" + match.source.sourceProductName + "\t" 
									+ match.source.sourceProductVersion + "\r\n");
						else if (match.rule.sourceTypeID == 1)
							bWriterResultsVerboseAddremoves.write(sourceScanPath + "\t"
									+ signature.publisherID + "\t" + signature.publisherName + "\t" + signature.webPage + "\t"
									+ signature.productID + "\t" + signature.productName + "\t" + signature.productLicensable + "\t"
									+ signature.productCategory + "\t" + signature.versionID + "\t" + signature.uniqueVersion + "\t"
									+ signature.build + "\t" + signature.major + "\t" + signature.minor + "\t"
									+ signature.edition + "\t" + signature.variation + "\t" + signature.licenseVersion + "\t"
									+ "addremove" + "\t" + match.source.sourceCompanyName + "\t" + match.source.sourceKeyOriginal + "\t" 
									+ match.source.sourceProductVersion + "\r\n");
					}
				else
					System.out.println("The signature for versionID: " + result.versionID + " is missing.");
			}
			bWriterResults.close();
			bWriterResultsVerboseAddremoves.close();
			bWriterResultsVerboseFiles.close();
		}
	}
	// end of ProcessScanTask class
	
	private static void processAllScans() throws IOException
	{
		Stopwatch timer = Stopwatch.createStarted();
		
		// write headers
		FileWriter fWriterResultsVerboseAddremoves = new FileWriter("s:\\results\\results_verbose_addremoves.txt");
		fWriterResultsVerboseAddremoves.write("SourceScanPath" + "\t"   
				+ "PublisherID" + "\t" + "PublisherName" + "\t" + "WebPage" + "\t"
				+ "ProductID" + "\t" + "ProductName" + "\t" + "Licensable" + "\t"
				+ "ProductCategory" + "\t" + "VersionID" + "\t" + "UniqueVersion" + "\t"
				+ "Build" + "\t" + "Major" + "\t" + "Minor" + "\t"
				+ "Edition" + "\t" + "Variation" + "\t" + "LicenseVersion" + "\t"
				+ "SourceType" + "\t" + "\t" + "SourceManufacturer" + "\t" + "SourceSoftwareName" + "\t"
				+ "SourceSoftwareVersion" + "\r\n");
		fWriterResultsVerboseAddremoves.close();
		
		FileWriter fWriterResultsVerboseFiles = new FileWriter("s:\\results\\results_verbose_files.txt");		
		fWriterResultsVerboseFiles.write("SourceScanPath" + "\t"   
					+ "PublisherID" + "\t" + "PublisherName" + "\t" + "WebPage" + "\t"
					+ "ProductID" + "\t" + "ProductName" + "\t" + "Licensable" + "\t"
					+ "ProductCategory" + "\t" + "VersionID" + "\t" + "UniqueVersion" + "\t"
					+ "Build" + "\t" + "Major" + "\t" + "Minor" + "\t"
					+ "Edition" + "\t" + "Variation" + "\t" + "LicenseVersion" + "\t"
					+ "SourceType" + "\t" + "\t" + "SourceManufacturer" + "\t" + "SourceFileName" + "\t"
					+ "SourceFileDescription" + "\t" + "SourceProductName" + "\t" + "SourceProductVersion" + "\r\n");
		fWriterResultsVerboseFiles.close();

		int noOfProcessors = Runtime.getRuntime().availableProcessors();
		System.out.println("Detected " + noOfProcessors + " processors!");
		
		// start thread pool
		ExecutorService executor = Executors.newFixedThreadPool((noOfProcessors > 1 ? noOfProcessors / 2: 1));
		System.out.println("Processing scans with " + (noOfProcessors > 1 ? noOfProcessors / 2: 1) + " worker threads!");

		// submit tasks to the thread pool
		for (File f : Files.fileTreeTraverser().preOrderTraversal(new File("s:\\scans\\")))
			if(f.isFile() && Files.getFileExtension(f.getPath()).equals("scan"))
				executor.execute(new ProcessScanTask(f.getPath()));
		
		// wait for the tasks to finish
		executor.shutdown();
		try {
			executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
		} catch (InterruptedException ex) {
			System.out.println(ex.toString());
		}
		
		logExecutionTime("processAllScans (Java): " + timer.stop().elapsed(TimeUnit.SECONDS));
	}
	
	private static void loadDiscoveryRules() throws IOException
	{
		String line;
		BufferedReader bReader;
		
		// load discovery rules
		bReader = new BufferedReader(
				new FileReader("s:\\library\\DiscoveryRules.txt"));
		int ruleID = 1;
		
		while ((line = bReader.readLine()) != null) {				
            String fields[] = line.split("\t", -1);
            
            DiscoveryRule rule = new DiscoveryRule();	  
            
            // autonumber
            rule.ruleID = ruleID++;	            
    		
            rule.versionID = Integer.parseInt(fields[0]);
    		rule.buildID = Integer.parseInt(fields[1]);
    		rule.sourceTypeID = Integer.parseInt(fields[2]);
    		
    		// uppercased for key usage
    		rule.ruleKeyUpperCase = fields[3].toUpperCase();
    		rule.ruleKeyOriginal = fields[3];	
    		
    		// simple glob style wildcard allowed, replace with .* for regex matching
    		rule.ruleProductVersion = fields[4];
    		if (rule.ruleProductVersion.contains("*")) {
    			rule.ruleProductVersion = rule.ruleProductVersion.replace("*", ".*");
    			rule.isRuleProductVersionRegex = true;
    		}
    		else
    			rule.isRuleProductVersionRegex = false;
    		
    		// simple glob style wildcard allowed, replace with .* and preappend (?i) for case insensitive regex matching
    		rule.ruleProductName = fields[5];
    		if (rule.ruleProductName.contains("*")) {
    			rule.ruleProductName = rule.ruleProductName.replace("*", ".*");
    			rule.ruleProductName = "(?i)" + rule.ruleProductName;
    			rule.isRuleProductNameRegex = true;
    		}
    		else
    			rule.isRuleProductNameRegex = false;
    		
    		// simple glob style wildcard allowed, replace with .* for regex matching
    		rule.ruleFileVersion = fields[6];
    		if (rule.ruleFileVersion.contains("*")) {
    			rule.ruleFileVersion = rule.ruleFileVersion.replace("*", ".*");
    			rule.isRuleFileVersionRegex = true;
    		}
    		else
    			rule.isRuleFileVersionRegex = false;
    		
    		rule.ruleFileSize = fields[7];	    		
    		
    		rule.ruleFilePath = fields[8];
    		// simple glob style wildcard allowed, replace with .* and preappend (?i) for case insensitive regex matching
    		if (rule.ruleFilePath.contains("*")) {
	    		rule.ruleFilePath = rule.ruleFilePath.replace("*", ".*");
	    		rule.ruleFilePath = "(?i)" + rule.ruleFilePath;
	    		// rule file path is always a regex whenever present so no need to set a separate boolean as in the previous ones
    		}
    		
    		discoveryRules.put(rule);
        }
		bReader.close();
		
		// load discovery version exclusion rules
		bReader = new BufferedReader(
				new FileReader("s:\\library\\DiscoveryVERs.txt"));
		
		while ((line = bReader.readLine()) != null) {
			String fields[] = line.split("\t");
			
			int excludedVersionID = Integer.parseInt(fields[0]);
			int versionID = Integer.parseInt(fields[1]);
			
			discoveryVERs.put(excludedVersionID, versionID);
		}
		bReader.close();
	}
	
	private static void loadDiscoverySignatures() throws IOException
	{
		String line;
		BufferedReader bReader;
		
		bReader = new BufferedReader(
				new FileReader("s:\\library\\DiscoverySignatures.txt"));
		
		while ((line = bReader.readLine()) != null) {				
            String fields[] = line.split("\t", -1);
            
			DiscoverySignature signature = new DiscoverySignature();
			signature.publisherID = Integer.parseInt(fields[0]);
			signature.publisherName = fields[1];
			signature.webPage = fields[2];
			signature.productID = Integer.parseInt(fields[3]);
			signature.productName = fields[4];
			signature.productLicensable = fields[5];
			signature.productCategory = fields[6];
			signature.versionID = Integer.parseInt(fields[7]);
			signature.uniqueVersion = fields[8];
			signature.build = fields[9];
			signature.major = fields[10];
			signature.minor = fields[11];
			signature.edition = fields[12];
			signature.variation = fields[13];
			signature.licenseVersion = fields[14];
			
			discoverySignatures.put(signature.versionID, signature);
		}
		bReader.close();
	}
	
	private static void saveDiscoveryAggregateResults() throws IOException
	{
		BufferedWriter bWriter = new BufferedWriter(
				new FileWriter("s:\\results\\results_aggregate.txt"));
		for (DiscoveryAggregateResult aggregateResult : discoveryAggregateResults.values())
			bWriter.write(aggregateResult.versionID + "\t" + aggregateResult.buildID + "\t" + aggregateResult.detectionPath
					+ "\t" + aggregateResult.count + "\t" + aggregateResult.scanPath + "\r\n");
		bWriter.close();
	}
	
	private static void saveDiscoveryAggregateSources() throws IOException
	{
		BufferedWriter bWriterAggregateAddremoves  = new BufferedWriter(
				new FileWriter("s:\\results\\aggregate_addremoves.txt"));
		BufferedWriter bWriterAggregateAddremovesUnused  = new BufferedWriter(
				new FileWriter("s:\\results\\aggregate_addremoves_unused.txt"));
		BufferedWriter bWriterAggregateFiles  = new BufferedWriter(
				new FileWriter("s:\\results\\aggregate_files.txt"));
		BufferedWriter bWriterAggregateFilesUnused  = new BufferedWriter(
				new FileWriter("s:\\results\\aggregate_files_unused.txt"));

		for (DiscoverySource source : discoveryAggregateSources.values())
		{
			if(source.sourceTypeID == 0)
			{
				bWriterAggregateFiles.write(source.sourceKeyOriginal + "\t" + source.sourceProductVersion + "\t" + source.sourceCompanyName + "\t"
					+ source.sourceProductName + "\t" + source.sourceFileDescription + "\t" + source.sourceFileVersion + "\t"	+ source.sourceFileSize + "\t" 
					+ source.sourceFilePath + "\t" + source.sourceScanPath + "\r\n");

				if (discoveryRules.get(0, source.sourceKeyUpperCase, source.sourceProductVersion).size() == 0)
				{
					bWriterAggregateFilesUnused.write(source.sourceKeyOriginal + "\t" + source.sourceProductVersion + "\t" + source.sourceCompanyName + "\t"
						+ source.sourceProductName + "\t" + source.sourceFileDescription + "\t" + source.sourceFileVersion + "\t"	+ source.sourceFileSize + "\t" 
						+ source.sourceFilePath + "\t" + source.sourceScanPath + "\r\n");
				}
			}
			else if (source.sourceTypeID == 1)
			{
				bWriterAggregateAddremoves.write(source.sourceKeyOriginal + "\t" + source.sourceProductVersion + "\t" + source.sourceCompanyName + "\t"
					//+ source.sourceInstalledLocation + "\t" + source.sourceUninstallString + "\t" + source.sourceOSComponent + "\t"
					+ source.sourceScanPath + "\r\n");

				if (discoveryRules.get(1, source.sourceKeyUpperCase, source.sourceProductVersion).size() == 0)
				{
					bWriterAggregateAddremovesUnused.write(source.sourceKeyOriginal + "\t" + source.sourceProductVersion + "\t" + source.sourceCompanyName + "\t"
					//+ source.sourceInstalledLocation + "\t" + source.sourceUninstallString + "\t" + source.sourceOSComponent + "\t" 
					+ source.sourceScanPath + "\r\n");
				}
			}
		}
		bWriterAggregateAddremoves.close();
		bWriterAggregateAddremovesUnused.close();
		bWriterAggregateFiles.close();
		bWriterAggregateFilesUnused.close();
	}
	
	private static void logExecutionTime(String str)
	{
		try {
			FileWriter fw = new FileWriter("s:\\logs\\execution_times.txt", true);
			fw.write(str + "\r\n");
			fw.close();
		}
		catch(IOException e){
			System.out.println (e.toString());
		}
	}
	
	public static void deleteFilesInFolder(File folder) {
	    File[] files = folder.listFiles();
	    if(files != null) //some JVMs return null for empty dirs
	        for(File f: files)
	            if(f.isFile())
	                f.delete();
	}
	
	public static void main(String[] args)
	{
		try {
			Stopwatch timer = Stopwatch.createStarted();
			
			deleteFilesInFolder(new File("s:\\results\\"));
			
			loadDiscoveryRules();
			loadDiscoverySignatures();
			
			processAllScans();
			
			saveDiscoveryAggregateResults();
			saveDiscoveryAggregateSources();
			
			logExecutionTime("Total (Java): " + timer.stop().elapsed(TimeUnit.SECONDS) + "\r\n");
		}
		catch(IOException ex) {
			System.out.println (ex.toString());
			System.exit(1);
		}
	}
}
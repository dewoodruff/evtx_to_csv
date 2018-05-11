# Given a Windows even log .evtx file, export a csv.
# ALL fields in the XML will be processed, so there will be a column for every unique field, 
# not just the main fields in the message.
# Note: this script is pretty slow

param (
    [string]$infile = $null
)

if (!$infile) {
    Write-Host "usage: evtx_to_csv.ps1 -infile <evtx file in>"
    exit
}

$initem = Get-Item $infile
$directory = $initem.Directory.FullName
$outfile=$($initem.BaseName + ".csv")


$output_file = [System.IO.StreamWriter] $("$directory\$outfile")

echo "Reading in the .evtx."
$events = get-winevent -path $infile

echo "Finding unique fields." 
# first pull out all unique field names
# iterate over every event and add the field names to an array. only add if they don't already exist in the array
$fields=@()
$fields += "Message"
#$fields += "TimeCreated"
foreach ($Event in $events) { 
    $xml = [xml]($Event.ToXml())
    foreach ($s in $xml.Event.System.ChildNodes) {
        if ($fields -notcontains $s.Name -and $s.Name -ne "Microsoft-Windows-Security-Auditing") {
            $fields += $s.Name
        }
    }
    foreach ($d in $xml.Event.EventData.Data) {
        if ($fields -notcontains $d.Name) {
            $fields += $d.Name
        }
    }
}

# build an array of events. each event is an element
$lines=@()
echo "Processing lines."
foreach ($Event in $events) { 
    # hash of fields and their values in this event
    $line=@{}
	$line.add("Message", ($Event.Message-split '\n')[0].replace("`n","").replace("`r",""))
    $line.add("TimeCreated", $Event.TimeCreated.ToString())
	$xml = [xml]($Event.ToXml())
    foreach ($s in $xml.Event.System.ChildNodes) {
		if ($s.InnerText) {
			$line.Add($s.Name, $s.InnerText)

		}
		#if ($s.Name -eq "TimeCreated") {
		#	echo $s
		#}
        
    }
    foreach ($d in $xml.Event.EventData.Data) {
        $text = $d.InnerText
        if ($text -eq $null) {
            $text = ""
        }
        # replace newlines with a string representing a newline
        # csv will be a mess without this
        $text = $text.replace("`n","\n").replace("`r","\n")
        # if something didn't parse correctly or is null, this will error and print out here
        try {
            $line.Add($d.Name, $text)
        }
        catch {
            echo $d
        }
    }
    $lines += $line
}
echo ("Processed " + $lines.Length + " events.")
# write the header
foreach ($field in $fields) {
    $output_file.Write($field + ",")
}
$output_file.WriteLine()

echo "Writing output file"
# loop through each line and add it to the csv
foreach ($line in $lines) {
    # check each line for a field matching every header value. 
    foreach ($field in $fields) {
        $output_file.Write($line.$field + ",")
    }
    $output_file.WriteLine()
}
$output_file.Flush()
$output_file.Close()
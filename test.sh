cd bin
for i in `ls ../vulnscripts`
do
	java braindeadanalyzer.Analyzer "/../vulnscripts/$i" > ../vulnreports/$i.txt
done

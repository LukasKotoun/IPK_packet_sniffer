All:
	dotnet publish -c Release -p:PublishSingleFile=true --no-self-contained -p:DebugType=None -o .
clean:
	rm ./ipk-sniffer

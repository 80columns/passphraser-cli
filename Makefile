default:
	dotnet build --configuration Release
debug:
	dotnet build
clean:
	rm -rf bin/ obj/

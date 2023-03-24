# Reproduce steps:
```sh
# 1. Build dll.
cd ./dll
go build -buildmode=c-shared -o="a.dll" "./dll.go"
# 2. Open the D3D12RaytracingHelloWorld.exe and set the pid to inject.
cd ../main
go run "./main.go"
```

# Resource
The D3D12RaytracingHelloWorld.exe program compiled from https://github.com/microsoft/DirectX-Graphics-Samples/blob/master/Samples/Desktop/D3D12Raytracing/src/D3D12RaytracingHelloWorld/readme.md
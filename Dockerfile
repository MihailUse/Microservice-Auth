FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
EXPOSE 80
EXPOSE 443

# copy csproj and restore as distinct layers
COPY *.sln .
COPY AuthMicroservice/*.csproj ./AuthMicroservice/
RUN dotnet restore

# copy everything else and build app
COPY AuthMicroservice/. ./AuthMicroservice/
WORKDIR /src/AuthMicroservice
RUN dotnet publish -c release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:6.0
WORKDIR /app
COPY --from=build /app ./
ENTRYPOINT ["dotnet", "AuthMicroservice.dll"]

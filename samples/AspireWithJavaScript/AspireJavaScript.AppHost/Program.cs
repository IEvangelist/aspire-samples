var builder = DistributedApplication.CreateBuilder(args);

var weatherApi = builder.AddProject<Projects.AspireJavaScript_MinimalApi>("weatherapi")
    .WithExternalHttpEndpoints();

var weatherApiHttp = weatherApi.GetEndpoint("http");
var weatherApiHttps = weatherApi.GetEndpoint("https");

DockerBuildArg[] buildArgs =
[
    new("services__weatherapi__https__0"),
    new("services__weatherapi__http__0"),
];

// Angular: npm run start
builder.AddNpmApp("angular", "../AspireJavaScript.Angular")
    .WithReference(weatherApi)
    .WithHttpEndpoint(env: "PORT")
    .WithExternalHttpEndpoints()
    .PublishAsDockerFile(buildArgs);

// React: npm run start
var react = builder.AddNpmApp("react", "../AspireJavaScript.React")
    .WithEnvironment("BROWSER", "none") // Disable opening browser on npm start
    .WithEnvironment("REACT_APP_WEATHER_API_HTTP", weatherApiHttp)
    .WithHttpEndpoint(env: "PORT")
    .WithExternalHttpEndpoints()
    .PublishAsDockerFile(buildArgs);

if (weatherApiHttps.IsAllocated)
{
    react.WithEnvironment("REACT_APP_WEATHER_API_HTTPS", weatherApiHttps);
}

// Vue: npm run dev
var vue = builder.AddNpmApp("vue", "../AspireJavaScript.Vue")
    .WithEnvironment("VITE_WEATHER_API_HTTP", weatherApiHttp)
    .WithHttpEndpoint(env: "PORT")
    .WithExternalHttpEndpoints()
    .PublishAsDockerFile(buildArgs);

if (weatherApiHttps.IsAllocated)
{
    vue.WithEnvironment("VITE_WEATHER_API_HTTPS", weatherApiHttps);
}

builder.Build().Run();

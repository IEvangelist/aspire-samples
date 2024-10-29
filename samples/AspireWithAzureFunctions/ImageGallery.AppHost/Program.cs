﻿var builder = DistributedApplication.CreateBuilder(args);

var storage = builder.AddAzureStorage("storage").RunAsEmulator();
var blobs = storage.AddBlobs("blobs");
var queues = storage.AddQueues("queues");

builder.AddAzureFunctionsProject<Projects.ImageGallery_Functions>("functions")
       .WithReference(queues)
       .WithReference(blobs)
       .WaitFor(storage);

builder.AddProject<Projects.ImageGallery_FrontEnd>("frontend")
       .WithReference(queues)
       .WithReference(blobs)
       .WaitFor(storage);

builder.Build().Run();

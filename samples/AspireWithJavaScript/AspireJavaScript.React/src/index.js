import React from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./components/App";

// const apiserver =
//   process.env.REACT_APP_WEATHER_API_HTTPS ||
//   process.env.REACT_APP_WEATHER_API_HTTP;
//weatherApi={`${apiserver}/weatherforecast`}

const container = document.getElementById("root");
const root = createRoot(container);
root.render(
  <React.StrictMode>
    <App weatherApi="http://localhost:5084/weatherforecast" />
  </React.StrictMode>
);

// map.tsx
import React, { useState, useEffect, useRef } from "react";
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  Polyline,
  useMap,
} from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// ---------------------- ICON ----------------------
const markerIcon = new L.Icon({
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
});

// ---------------------- SEARCHBAR ----------------------
const useDebounce = (value: string, delay: number) => {
  const [debouncedValue, setDebouncedValue] = useState(value);
  useEffect(() => {
    const handler = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(handler);
  }, [value, delay]);
  return debouncedValue;
};

const SearchBar = ({
  setDestination,
}: {
  setDestination: (coords: [number, number]) => void;
}) => {
  const [input, setInput] = useState("");
  const [suggestions, setSuggestions] = useState<any[]>([]);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const debouncedInput = useDebounce(input, 300);

  useEffect(() => {
    if (!debouncedInput.trim()) {
      setSuggestions([]);
      return;
    }
    const fetchSuggestions = async () => {
      try {
        const res = await fetch(
          `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(
            debouncedInput
          )}`
        );
        const data = await res.json();
        setSuggestions(data || []);
      } catch (err) {
        setSuggestions([]);
      }
    };
    fetchSuggestions();
  }, [debouncedInput]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setSuggestions([]);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSelect = (s: any) => {
    setInput(s.display_name);
    setDestination([parseFloat(s.lat), parseFloat(s.lon)]);
    setSuggestions([]);
  };

  const handleSearchClick = async () => {
    if (!input.trim()) return;
    try {
      const res = await fetch(
        `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(input)}`
      );
      const data = await res.json();
      if (data && data[0]) {
        setDestination([parseFloat(data[0].lat), parseFloat(data[0].lon)]);
        setSuggestions([]);
      } else {
        alert("Destination not found.");
      }
    } catch (err) {
      alert("Error searching destination.");
    }
  };

  return (
    <div ref={wrapperRef} style={{ position: "relative", width: "100%" }}>
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Enter destination..."
        style={{
          padding: "10px",
          borderRadius: "8px",
          border: "none",
          outline: "none",
          fontSize: "14px",
          width: "100%",
          boxSizing: "border-box",
          color: "#000",
          background: "#fff",
        }}
      />

      {suggestions.length > 0 && (
        <ul
          style={{
            position: "absolute",
            top: "48px",
            width: "100%",
            maxHeight: "200px",
            overflowY: "auto",
            background: "#fff",
            borderRadius: "8px",
            boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
            padding: 0,
            margin: 0,
            listStyle: "none",
            zIndex: 1000,
          }}
        >
          {suggestions.map((s, idx) => (
            <li
              key={idx}
              onClick={() => handleSelect(s)}
              style={{
                padding: "10px",
                cursor: "pointer",
                borderBottom: "1px solid #e5e7eb",
                color: "#000",
              }}
            >
              {s.display_name}
            </li>
          ))}
        </ul>
      )}

      <button
        onClick={handleSearchClick}
        style={{
          marginTop: "8px",
          width: "100%",
          padding: "10px",
          background: "#3b82f6",
          color: "#fff",
          border: "none",
          borderRadius: "8px",
          cursor: "pointer",
        }}
      >
        🔍 Search
      </button>
    </div>
  );
};

// ---------------------- FLY TO LOCATION ----------------------
const FlyToLocation = ({ coords }: { coords: [number, number] }) => {
  const map = useMap();
  useEffect(() => {
    if (coords) map.flyTo(coords, 13);
  }, [coords]);
  return null;
};

// ---------------------- MAP ----------------------
interface MapProps {
  autoDestination?: {
    lat: number;
    lng: number;
    name?: string;
  } | null;
  hideSearchBar?: boolean;
}

const Map = ({ autoDestination = null, hideSearchBar = false }: MapProps) => {
  const [position, setPosition] = useState<[number, number] | null>(null);
  const [destination, setDestination] = useState<[number, number] | null>(null);
  const [destinationName, setDestinationName] = useState<string>("");
  const [route, setRoute] = useState<[number, number][]>([]);
  const [distance, setDistance] = useState<number | null>(null);
  const [duration, setDuration] = useState<number | null>(null);
  const [recommendation, setRecommendation] = useState<string>("");
  const [isLoadingRoute, setIsLoadingRoute] = useState(false);

  // Get user location on mount
  useEffect(() => {
    navigator.geolocation.getCurrentPosition(
      (pos) => setPosition([pos.coords.latitude, pos.coords.longitude]),
      () => alert("Failed to get your location. Please enable location services.")
    );
  }, []);

  // Handle auto-destination from props
  useEffect(() => {
    if (autoDestination) {
      const destCoords: [number, number] = [autoDestination.lat, autoDestination.lng];
      setDestination(destCoords);
      setDestinationName(autoDestination.name || "Selected Destination");
    }
  }, [autoDestination]);

  useEffect(() => {
    const getRoute = async () => {
      if (!position || !destination) return;

      setIsLoadingRoute(true);
      try {
        const url = `https://router.project-osrm.org/route/v1/driving/${position[1]},${position[0]};${destination[1]},${destination[0]}?overview=full&geometries=geojson`;
        const res = await fetch(url);
        const data = await res.json();

        if (data.routes && data.routes.length > 0) {
          const routeCoords = data.routes[0].geometry.coordinates.map(
            (c: number[]) => [c[1], c[0]]
          );
          setRoute(routeCoords);
          setDistance(data.routes[0].distance / 1000);
          setDuration(data.routes[0].duration / 60);

          const km = data.routes[0].distance / 1000;
          if (km < 10)
            setRecommendation(
              "🚌 Take a tricycle, jeepney, or walk if nearby. Quick and easy!"
            );
          else if (km < 80)
            setRecommendation(
              "🚐 Try taking a bus or van — affordable and frequent rides available."
            );
          else
            setRecommendation(
              "🚗 Best to drive your own vehicle or rent one for comfort and time efficiency."
            );
        }
      } catch (err) {
        console.error("Failed to fetch route", err);
      } finally {
        setIsLoadingRoute(false);
      }
    };

    getRoute();
  }, [position, destination]);

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden", borderRadius: "16px" }}>
      {/* SIDEBAR */}
      <div
        style={{
          width: "320px",
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
          color: "#fff",
          background: "#1e293b",
          zIndex: 1000,
        }}
      >
        {destinationName && (
          <div
            style={{
              background: "#059669",
              borderRadius: "10px",
              padding: "12px",
              fontSize: "14px",
              fontWeight: 600,
            }}
          >
            📍 Navigating to: {destinationName}
          </div>
        )}

        {!hideSearchBar && (
          <>
            <h3 style={{ color: "#38bdf8", fontWeight: "600", fontSize: "18px" }}>
              Search Destination
            </h3>
            <SearchBar setDestination={(coords) => {
              setDestination(coords);
              setDestinationName("");
            }} />
          </>
        )}

        {isLoadingRoute && (
          <div
            style={{
              background: "#334155",
              borderRadius: "10px",
              padding: "15px",
              textAlign: "center",
              fontSize: "14px",
            }}
          >
            🔄 Calculating route...
          </div>
        )}

        {distance && duration && !isLoadingRoute && (
          <div
            style={{
              background: "#334155",
              borderRadius: "10px",
              padding: "15px",
              display: "flex",
              flexDirection: "column",
              gap: "6px",
              marginTop: "10px",
            }}
          >
            <div style={{ fontSize: "15px", fontWeight: 500 }}>
              🚗 <strong>{distance.toFixed(2)} km</strong>
            </div>
            <div style={{ fontSize: "14px" }}>⏱️ {Math.round(duration)} min</div>
            {recommendation && (
              <div
                style={{
                  marginTop: "8px",
                  padding: "10px",
                  background: "#1e3a8a",
                  borderRadius: "8px",
                  fontSize: "13px",
                  lineHeight: "1.4",
                }}
              >
                {recommendation}
              </div>
            )}
          </div>
        )}

        <button
          onClick={() =>
            navigator.geolocation.getCurrentPosition(
              (pos) => setPosition([pos.coords.latitude, pos.coords.longitude]),
              () => alert("Unable to get your location.")
            )
          }
          style={{
            background: "#f43f5e",
            color: "#fff",
            padding: "10px",
            border: "none",
            borderRadius: "8px",
            cursor: "pointer",
            width: "100%",
            marginTop: "20px",
          }}
        >
          📍 Use My Location
        </button>
      </div>

      {/* MAP */}
      <div style={{ flex: 1, height: "100%" }}>
        <MapContainer
          center={position || [13.143, 123.735]}
          zoom={10}
          style={{ height: "100%", width: "100%" }}
        >
          <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          {position && (
            <Marker position={position} icon={markerIcon}>
              <Popup>Your location</Popup>
            </Marker>
          )}
          {destination && (
            <Marker position={destination} icon={markerIcon}>
              <Popup>{destinationName || "Destination"}</Popup>
            </Marker>
          )}
          {route.length > 0 && <Polyline positions={route} color="#38bdf8" weight={5} />}
          {destination && <FlyToLocation coords={destination} />}
        </MapContainer>
      </div>
    </div>
  );
};

export default Map;

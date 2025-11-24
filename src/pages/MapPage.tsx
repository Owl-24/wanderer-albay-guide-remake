import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import Navbar from "@/components/Navbar";
import { Card } from "@/components/ui/card";
import Map from "@/components/Map";

const MapPage = () => {
  const [searchParams] = useSearchParams();
  const [autoDestination, setAutoDestination] = useState<{
    lat: number;
    lng: number;
    name?: string;
  } | null>(null);

  useEffect(() => {
    const lat = searchParams.get("lat");
    const lng = searchParams.get("lng");
    const name = searchParams.get("name");

    if (lat && lng) {
      setAutoDestination({
        lat: parseFloat(lat),
        lng: parseFloat(lng),
        name: name || undefined,
      });
    }
  }, [searchParams]);

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <div className="container py-12">
        <div className="text-center mb-8 animate-fade-in">
          <h1 className="text-4xl md:text-5xl font-bold mb-4">
            Interactive <span className="text-primary">Map</span>
          </h1>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            {autoDestination?.name 
              ? `Navigate to ${autoDestination.name}` 
              : "Explore all tourist destinations across Albay on an interactive, free map powered by OpenStreetMap"}
          </p>
        </div>

        <div className="h-[600px]">
          <Card className="overflow-hidden h-full">
            <Map autoDestination={autoDestination} />
          </Card>
        </div>
      </div>
    </div>
  );
};

export default MapPage;

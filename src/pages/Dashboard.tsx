import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "@/components/Navbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import { ProfileEditor } from "@/components/profile/ProfileEditor";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { supabase } from "@/integrations/supabase/client";
import { Session } from "@supabase/supabase-js";
import { toast } from "sonner";
import { MapPin, Trash2, Calendar, Sparkles, Edit, RefreshCw } from "lucide-react";
import { OnboardingModal } from "@/components/OnboardingModal";
import RecommendedSpots from "@/components/RecommendedSpots";
import EventNotifications from "@/components/EventNotifications";
import NearbyRestaurants from "@/components/NearbyRestaurants";
import WeatherWidget from "@/components/WeatherWidget";

interface Itinerary {
  id: string;
  name: string;
  selected_categories: string[];
  spots: any[];
  created_at: string;
}

const Dashboard = () => {
  const navigate = useNavigate();
  const [session, setSession] = useState<Session | null>(null);
  const [itineraries, setItineraries] = useState<Itinerary[]>([]);
  const [profile, setProfile] = useState<any>(null);
  const [showOnboarding, setShowOnboarding] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      if (!session) {
        navigate("/auth");
      } else {
        fetchProfile(session.user.id);
        fetchItineraries(session.user.id);
      }
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      if (!session) {
        navigate("/auth");
      }
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  const fetchProfile = async (userId: string) => {
    const { data } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", userId)
      .single();
    
    if (data) {
      setProfile(data);
      // Show onboarding if user hasn't completed it (check user_preferences instead)
      if (!data.user_preferences) {
        setShowOnboarding(true);
      }
    }
  };

  const fetchItineraries = async (userId: string) => {
    const { data, error } = await supabase
      .from("itineraries")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (!error && data) {
      setItineraries(data as Itinerary[]);
    }
  };

  const deleteItinerary = async (id: string) => {
    const { error } = await supabase.from("itineraries").delete().eq("id", id);

    if (error) {
      toast.error("Failed to delete itinerary");
    } else {
      toast.success("Itinerary deleted");
      setItineraries(itineraries.filter((i) => i.id !== id));
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      {session && (
        <OnboardingModal
          open={showOnboarding}
          onComplete={() => {
            setShowOnboarding(false);
            fetchProfile(session.user.id);
          }}
          userId={session.user.id}
        />
      )}

      <div className="container py-12">
        <div className="max-w-5xl mx-auto">
          <div className="mb-12 animate-fade-in">
            <div className="flex items-start gap-6 mb-8">
              <Avatar className="w-24 h-24 border-4 border-primary/20">
                <AvatarImage src={profile?.avatar_url || ""} alt={profile?.full_name || "User"} />
                <AvatarFallback className="text-3xl bg-primary/10">
                  {profile?.full_name ? profile.full_name.charAt(0).toUpperCase() : "U"}
                </AvatarFallback>
              </Avatar>
              <div className="flex-1">
                <div className="flex items-start justify-between">
                  <div>
                    <h1 className="text-4xl md:text-5xl font-bold mb-2">
                      Welcome back, <span className="text-primary">{profile?.full_name || "Traveler"}</span>
                    </h1>
                    {profile?.bio && (
                      <p className="text-base text-muted-foreground mb-2 max-w-2xl">
                        {profile.bio}
                      </p>
                    )}
                    <p className="text-lg text-muted-foreground">
                      Manage your travel plans and explore new destinations
                    </p>
                  </div>
                  <Dialog>
                    <DialogTrigger asChild>
                      <Button variant="outline" className="hidden md:flex">
                        <Edit className="w-4 h-4 mr-2" />
                        Edit Profile
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="max-w-md">
                      <DialogHeader>
                        <DialogTitle>Edit Profile</DialogTitle>
                      </DialogHeader>
                      {session && (
                        <ProfileEditor
                          userId={session.user.id}
                          currentName={profile?.full_name || null}
                          currentBio={profile?.bio || null}
                          currentAvatarUrl={profile?.avatar_url || null}
                          onProfileUpdated={() => fetchProfile(session.user.id)}
                        />
                      )}
                    </DialogContent>
                  </Dialog>
                </div>
              </div>
            </div>
          </div>

          {/* Event Notifications */}
          {profile?.user_preferences?.districts && (
            <EventNotifications userDistricts={profile.user_preferences.districts} />
          )}

          {/* Personalized Recommendations */}
          {profile?.user_preferences && (
            <div className="mb-12 animate-fade-in">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-3xl font-bold mb-2">
                    Your Recommended Destinations 🌋
                  </h2>
                  <p className="text-muted-foreground">
                    Curated based on your travel preferences
                  </p>
                </div>
                <Button 
                  variant="outline" 
                  onClick={() => setShowOnboarding(true)}
                  className="gap-2"
                >
                  <RefreshCw className="w-4 h-4" />
                  Edit Preferences
                </Button>
              </div>
              <RecommendedSpots 
                preferences={profile.user_preferences} 
                userId={session?.user?.id}
              />
            </div>
          )}

          {/* Nearby Restaurants */}
          {profile?.user_preferences?.districts && profile?.user_preferences?.interests && (
            <NearbyRestaurants 
              userDistricts={profile.user_preferences.districts}
              userInterests={profile.user_preferences.interests}
            />
          )}

          {/* Quick Actions */}
          <div className="mb-12">
            <h2 className="text-2xl font-bold mb-6">Quick Actions</h2>
            <div className="grid md:grid-cols-3 gap-6">
              <Card className="cursor-pointer hover:shadow-lg transition-all" onClick={() => navigate("/itinerary")}>
                <CardContent className="p-6 text-center">
                  <Sparkles className="w-12 h-12 mx-auto mb-4 text-primary" />
                  <h3 className="font-semibold text-lg mb-2">Build New Itinerary</h3>
                  <p className="text-sm text-muted-foreground">Create a personalized travel plan</p>
                </CardContent>
              </Card>

              <Card className="cursor-pointer hover:shadow-lg transition-all" onClick={() => navigate("/explore")}>
                <CardContent className="p-6 text-center">
                  <MapPin className="w-12 h-12 mx-auto mb-4 text-accent" />
                  <h3 className="font-semibold text-lg mb-2">Explore All Destinations</h3>
                  <p className="text-sm text-muted-foreground">Browse all tourist spots in Albay</p>
                </CardContent>
              </Card>

              <Card className="cursor-pointer hover:shadow-lg transition-all" onClick={() => navigate("/map")}>
                <CardContent className="p-6 text-center">
                  <MapPin className="w-12 h-12 mx-auto mb-4 text-secondary" />
                  <h3 className="font-semibold text-lg mb-2">View Map</h3>
                  <p className="text-sm text-muted-foreground">See all locations on the map</p>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Saved Itineraries */}
<div>
  <h2 className="text-2xl font-bold mb-6">Your Itineraries</h2>

  {itineraries.length > 0 ? (
    <div className="space-y-4">
      {itineraries.map((itinerary) => (
        <Dialog key={itinerary.id}>
          <DialogTrigger asChild>
            <Card className="hover:shadow-lg transition-all cursor-pointer">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <CardTitle className="mb-2">{itinerary.name}</CardTitle>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground mb-3">
                      <Calendar className="w-4 h-4" />
                      {new Date(itinerary.created_at).toLocaleDateString()}
                    </div>
                    <div className="flex flex-wrap gap-2 mb-3">
                      {itinerary.selected_categories.map((cat) => (
                        <Badge key={cat} variant="secondary">
                          {cat}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <Button
                    variant="destructive"
                    size="icon"
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteItinerary(itinerary.id);
                    }}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-3">
                  {itinerary.spots.length} destinations
                </p>
                <div className="space-y-2">
                  {itinerary.spots.slice(0, 3).map((spot: any, idx: number) => (
                    <div 
                      key={idx} 
                      className="flex items-center gap-2 text-sm cursor-pointer hover:text-primary transition-colors"
                      onClick={(e) => {
                        e.stopPropagation();
                        if (spot.latitude && spot.longitude) {
                          navigate(`/map?lat=${spot.latitude}&lng=${spot.longitude}&name=${encodeURIComponent(spot.name)}`);
                        } else {
                          toast.error("Location coordinates not available");
                        }
                      }}
                    >
                      <MapPin className="w-4 h-4 text-primary" />
                      <span className="hover:underline">{spot.name}</span>
                    </div>
                  ))}
                  {itinerary.spots.length > 3 && (
                    <p className="text-sm text-muted-foreground">
                      +{itinerary.spots.length - 3} more destinations
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          </DialogTrigger>

          {/* Full Itinerary View */}
          <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold mb-2">
                {itinerary.name}
              </DialogTitle>
              <p className="text-sm text-muted-foreground mb-4">
                Created on {new Date(itinerary.created_at).toLocaleDateString()}
              </p>
              <div className="flex flex-wrap gap-2 mb-4">
                {itinerary.selected_categories.map((cat) => (
                  <Badge key={cat} variant="secondary">
                    {cat}
                  </Badge>
                ))}
              </div>
            </DialogHeader>

            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Destinations</h3>
              {itinerary.spots.length > 0 ? (
                itinerary.spots.map((spot: any, idx: number) => (
                  <div
                    key={idx}
                    className="flex items-start gap-3 border-b pb-3 cursor-pointer hover:bg-accent/50 p-2 rounded-lg transition-colors"
                    onClick={() => {
                      if (spot.latitude && spot.longitude) {
                        navigate(`/map?lat=${spot.latitude}&lng=${spot.longitude}&name=${encodeURIComponent(spot.name)}`);
                      } else {
                        toast.error("Location coordinates not available for this spot");
                      }
                    }}
                  >
                    <MapPin className="w-5 h-5 mt-1 text-primary" />
                    <div className="flex-1">
                      <p className="font-medium">{spot.name}</p>
                      {spot.description && (
                        <p className="text-sm text-muted-foreground">
                          {spot.description}
                        </p>
                      )}
                      {spot.location && (
                        <p className="text-xs text-muted-foreground italic">
                          📍 {spot.location}
                        </p>
                      )}
                      {spot.latitude && spot.longitude && (
                        <Button 
                          variant="ghost" 
                          size="sm" 
                          className="mt-2 text-primary hover:text-primary"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/map?lat=${spot.latitude}&lng=${spot.longitude}&name=${encodeURIComponent(spot.name)}`);
                          }}
                        >
                          🗺️ View Route
                        </Button>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-muted-foreground text-sm">
                  No destinations added yet.
                </p>
              )}
            </div>
          </DialogContent>
        </Dialog>
      ))}
    </div>
  ) : (
    <Card>
      <CardContent className="p-12 text-center">
        <Sparkles className="w-16 h-16 mx-auto mb-4 text-muted-foreground" />
        <h3 className="text-lg font-semibold mb-2">No itineraries yet</h3>
        <p className="text-muted-foreground mb-6">
          Start planning your adventure by creating your first itinerary
        </p>
        <Button onClick={() => navigate("/itinerary")}>
          <Sparkles className="w-4 h-4 mr-2" />
          Build Itinerary
        </Button>
      </CardContent>
    </Card>
  )}
</div>

        </div>
      </div>
    </div>
  );
};

export default Dashboard;

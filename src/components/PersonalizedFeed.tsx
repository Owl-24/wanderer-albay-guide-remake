import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { MapPin, Star, Eye, Heart, Utensils, Bed, CheckCircle } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useNavigate } from "react-router-dom";
import { useFavorites } from "@/hooks/useFavorites";
import { Skeleton } from "@/components/ui/skeleton";

interface TouristSpot {
  id: string;
  name: string;
  description: string;
  location: string;
  municipality: string;
  category: string[];
  image_url: string;
  rating: number;
  is_hidden_gem: boolean;
}

interface Accommodation {
  id: string;
  name: string;
  description: string;
  location: string;
  municipality: string;
  category: string[];
  image_url: string;
  price_range: string;
  rating: number;
}

interface Restaurant {
  id: string;
  name: string;
  description: string;
  location: string;
  municipality: string;
  food_type: string;
  image_url: string;
}

interface PersonalizedFeedProps {
  userId: string;
}

const PersonalizedFeed = ({ userId }: PersonalizedFeedProps) => {
  const [spots, setSpots] = useState<TouristSpot[]>([]);
  const [accommodations, setAccommodations] = useState<Accommodation[]>([]);
  const [restaurants, setRestaurants] = useState<Restaurant[]>([]);
  const [preferences, setPreferences] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [autoAddEnabled, setAutoAddEnabled] = useState(false);
  const [addedToItinerary, setAddedToItinerary] = useState<Set<string>>(new Set());
  const navigate = useNavigate();
  const { favorites, visited, toggleFavorite, markAsVisited, isFavorite, isVisited } = useFavorites(userId);

  useEffect(() => {
    fetchUserPreferences();
  }, [userId]);

  useEffect(() => {
    if (preferences) {
      fetchPersonalizedContent();
    }
  }, [preferences]);

  useEffect(() => {
    if (autoAddEnabled && spots.length > 0) {
      handleAutoAddRecommendations();
    }
  }, [autoAddEnabled, spots]);

  const fetchUserPreferences = async () => {
    try {
      const { data, error } = await supabase
        .from("profiles")
        .select("user_preferences")
        .eq("id", userId)
        .single();

      if (error) throw error;
      if (data?.user_preferences) {
        setPreferences(data.user_preferences);
      }
    } catch (error) {
      console.error("Error fetching preferences:", error);
    }
  };

  const fetchPersonalizedContent = async () => {
    setLoading(true);
    try {
      // Fetch tourist spots based on preferences
      await fetchSpots();
      // Fetch accommodations based on preferences
      await fetchAccommodations();
      // Fetch restaurants based on district preferences
      await fetchRestaurants();
    } catch (error) {
      console.error("Error fetching personalized content:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchSpots = async () => {
    const { data, error } = await supabase
      .from("tourist_spots")
      .select("*");

    if (error) {
      console.error("Error fetching spots:", error);
      return;
    }

    if (data) {
      // Filter and score based on user preferences
      const scoredSpots = data.map(spot => {
        let score = 0;

        // Match categories
        if (preferences.categories && spot.category) {
          const matchingCategories = preferences.categories.filter((cat: string) => 
            spot.category.some((spotCat: string) => 
              spotCat.toLowerCase().includes(cat.toLowerCase()) ||
              cat.toLowerCase().includes(spotCat.toLowerCase())
            )
          );
          score += matchingCategories.length * 5;
        }

        // Match subcategories (interests)
        if (preferences.subcategories && spot.category) {
          const matchingSubcategories = preferences.subcategories.filter((sub: string) => 
            spot.category.some((spotCat: string) => 
              spotCat.toLowerCase().includes(sub.toLowerCase())
            )
          );
          score += matchingSubcategories.length * 3;
        }

        // Match districts
        if (preferences.districts && spot.municipality) {
          const districtMatch = preferences.districts.some((district: string) => {
            if (district === "District 1") {
              return ["Bacacay", "Malilipot", "Malinao", "Santo Domingo", "Tiwi", "Tabaco"].some(m => 
                spot.municipality?.includes(m)
              );
            }
            if (district === "District 2") {
              return ["Legazpi", "Camalig", "Daraga", "Manito", "Rapu-Rapu"].some(m => 
                spot.municipality?.includes(m)
              );
            }
            if (district === "District 3") {
              return ["Guinobatan", "Ligao", "Oas", "Pio Duran", "Polangui", "Jovellar"].some(m => 
                spot.municipality?.includes(m)
              );
            }
            return false;
          });
          if (districtMatch) score += 10;
        }

        // Boost hidden gems
        if (spot.is_hidden_gem) score += 5;

        // Boost highly rated spots
        if (spot.rating) score += (spot.rating / 5) * 3;

        return { ...spot, score };
      });

      // Only show spots with positive scores (matching preferences)
      const filteredSpots = scoredSpots
        .filter(spot => spot.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, 6);

      setSpots(filteredSpots);
    }
  };

  const fetchAccommodations = async () => {
    const { data, error } = await supabase
      .from("accommodations")
      .select("*");

    if (error) {
      console.error("Error fetching accommodations:", error);
      return;
    }

    if (data) {
      // Filter accommodations based on district preferences
      const filtered = data.filter(acc => {
        if (!preferences.districts || preferences.districts.length === 0) return true;
        
        return preferences.districts.some((district: string) => {
          if (district === "District 1") {
            return ["Bacacay", "Malilipot", "Malinao", "Santo Domingo", "Tiwi", "Tabaco"].some(m => 
              acc.municipality?.includes(m)
            );
          }
          if (district === "District 2") {
            return ["Legazpi", "Camalig", "Daraga", "Manito", "Rapu-Rapu"].some(m => 
              acc.municipality?.includes(m)
            );
          }
          if (district === "District 3") {
            return ["Guinobatan", "Ligao", "Oas", "Pio Duran", "Polangui", "Jovellar"].some(m => 
              acc.municipality?.includes(m)
            );
          }
          return false;
        });
      });

      setAccommodations(filtered.slice(0, 6));
    }
  };

  const fetchRestaurants = async () => {
    const { data, error } = await supabase
      .from("restaurants")
      .select("*");

    if (error) {
      console.error("Error fetching restaurants:", error);
      return;
    }

    if (data) {
      // Filter restaurants based on district preferences
      const filtered = data.filter(rest => {
        if (!preferences.districts || preferences.districts.length === 0) return true;
        
        return preferences.districts.some((district: string) => {
          if (district === "District 1") {
            return ["Bacacay", "Malilipot", "Malinao", "Santo Domingo", "Tiwi", "Tabaco"].some(m => 
              rest.municipality?.includes(m)
            );
          }
          if (district === "District 2") {
            return ["Legazpi", "Camalig", "Daraga", "Manito", "Rapu-Rapu"].some(m => 
              rest.municipality?.includes(m)
            );
          }
          if (district === "District 3") {
            return ["Guinobatan", "Ligao", "Oas", "Pio Duran", "Polangui", "Jovellar"].some(m => 
              rest.municipality?.includes(m)
            );
          }
          return false;
        });
      });

      setRestaurants(filtered.slice(0, 6));
    }
  };

  const addToItinerary = async (item: TouristSpot | Accommodation | Restaurant, type: 'spot' | 'accommodation' | 'restaurant') => {
    try {
      // Check if user already has an itinerary
      const { data: existingItinerary, error: fetchError } = await supabase
        .from("itineraries")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(1)
        .single();

      if (fetchError && fetchError.code !== 'PGRST116') {
        console.error("Error fetching itinerary:", fetchError);
        return;
      }

      // Include complete data with coordinates for spots
      const itemData: any = {
        id: item.id,
        name: item.name,
        location: item.location,
        description: item.description,
        type: type
      };

      // Add coordinates for tourist spots and accommodations
      if ('latitude' in item && 'longitude' in item) {
        itemData.latitude = item.latitude;
        itemData.longitude = item.longitude;
      }

      if (existingItinerary) {
        // Update existing itinerary
        const currentSpots = Array.isArray(existingItinerary.spots) ? existingItinerary.spots : [];
        const alreadyAdded = currentSpots.some((s: any) => s.id === item.id);
        
        if (!alreadyAdded) {
          const { error: updateError } = await supabase
            .from("itineraries")
            .update({
              spots: [...currentSpots, itemData] as any
            })
            .eq("id", existingItinerary.id);

          if (updateError) {
            console.error("Error updating itinerary:", updateError);
          } else {
            setAddedToItinerary(prev => new Set(prev).add(item.id));
          }
        }
      } else {
        // Create new itinerary
        const { error: insertError } = await supabase
          .from("itineraries")
          .insert({
            user_id: userId,
            name: "My Personalized Itinerary",
            spots: [itemData],
            selected_categories: preferences.categories || []
          });

        if (insertError) {
          console.error("Error creating itinerary:", insertError);
        } else {
          setAddedToItinerary(prev => new Set(prev).add(item.id));
        }
      }
    } catch (error) {
      console.error("Error adding to itinerary:", error);
    }
  };

  const handleAutoAddRecommendations = async () => {
    // Auto-add top 5 recommended spots to itinerary
    const topSpots = spots.slice(0, 5);
    for (const spot of topSpots) {
      if (!addedToItinerary.has(spot.id)) {
        await addToItinerary(spot, 'spot');
      }
    }
  };

  if (loading) {
    return (
      <div className="space-y-12">
        <div>
          <Skeleton className="h-8 w-64 mb-6" />
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3].map((i) => (
              <Card key={i}>
                <Skeleton className="h-48 w-full" />
                <CardContent className="p-4">
                  <Skeleton className="h-6 w-3/4 mb-2" />
                  <Skeleton className="h-4 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (!preferences) {
    return null;
  }

  return (
    <div className="space-y-12 animate-fade-in">
      {/* Auto-Add Toggle */}
      <Card className="bg-primary/5 border-primary/20">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-lg mb-1">Auto-Add Recommendations</h3>
              <p className="text-sm text-muted-foreground">
                Automatically add top recommended spots to your itinerary based on your preferences
              </p>
            </div>
            <Button
              variant={autoAddEnabled ? "default" : "outline"}
              onClick={() => setAutoAddEnabled(!autoAddEnabled)}
            >
              {autoAddEnabled ? "Enabled" : "Enable Auto-Add"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Personalized Tourist Spots */}
      {spots.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-3xl font-bold mb-2">Perfect Spots For You</h2>
              <p className="text-muted-foreground">Based on your interests in {preferences.categories?.join(", ")}</p>
            </div>
            <Button variant="outline" onClick={() => navigate("/explore")}>
              View All
            </Button>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {spots.map((spot) => (
              <Card 
                key={spot.id} 
                className="group cursor-pointer hover:shadow-xl transition-all overflow-hidden"
                onClick={() => navigate(`/spot/${spot.id}`)}
              >
                <div className="relative h-56 overflow-hidden">
                  <img
                    src={spot.image_url || "/placeholder.svg"}
                    alt={spot.name}
                    className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300"
                  />
                  {spot.is_hidden_gem && (
                    <Badge className="absolute top-3 right-3 bg-primary/90 backdrop-blur-sm">
                      💎 Hidden Gem
                    </Badge>
                  )}
                  <div className="absolute inset-0 bg-gradient-to-t from-background/80 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <CardContent className="p-4">
                  <h3 className="font-semibold text-lg mb-2 line-clamp-1 group-hover:text-primary transition-colors">
                    {spot.name}
                  </h3>
                  <div className="flex items-center gap-1 text-sm text-muted-foreground mb-2">
                    <MapPin className="w-4 h-4" />
                    <span className="line-clamp-1">{spot.municipality || spot.location}</span>
                  </div>
                  <div className="flex items-center gap-2 mb-3">
                    {spot.rating > 0 && (
                      <div className="flex items-center gap-1">
                        <Star className="w-4 h-4 fill-yellow-400 text-yellow-400" />
                        <span className="text-sm font-medium">{spot.rating.toFixed(1)}</span>
                      </div>
                    )}
                    {spot.category && spot.category.length > 0 && (
                      <Badge variant="secondary" className="text-xs">
                        {spot.category[0]}
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
                    {spot.description}
                  </p>
                  <div className="flex gap-2 mb-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="flex-1"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/spot/${spot.id}`);
                      }}
                    >
                      <Eye className="w-4 h-4 mr-2" />
                      Details
                    </Button>
                    <Button
                      variant={isFavorite(spot.id) ? "default" : "outline"}
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleFavorite(spot.id);
                      }}
                    >
                      <Heart className={`w-4 h-4 ${isFavorite(spot.id) ? 'fill-current' : ''}`} />
                    </Button>
                  </div>
                  <Button
                    variant={addedToItinerary.has(spot.id) ? "secondary" : "default"}
                    size="sm"
                    className="w-full"
                    onClick={(e) => {
                      e.stopPropagation();
                      addToItinerary(spot, 'spot');
                    }}
                    disabled={addedToItinerary.has(spot.id)}
                  >
                    {addedToItinerary.has(spot.id) ? (
                      <>
                        <CheckCircle className="w-4 h-4 mr-1" />
                        Added to Itinerary
                      </>
                    ) : (
                      "Add to Itinerary"
                    )}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>
      )}

      {/* Recommended Accommodations */}
      {accommodations.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-3xl font-bold mb-2">Recommended Stays</h2>
              <p className="text-muted-foreground">Accommodations in your preferred areas</p>
            </div>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {accommodations.map((acc) => (
              <Card key={acc.id} className="hover:shadow-lg transition-shadow">
                <div className="relative h-48 overflow-hidden rounded-t-lg">
                  <img
                    src={acc.image_url || "/placeholder.svg"}
                    alt={acc.name}
                    className="w-full h-full object-cover"
                  />
                </div>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-semibold text-lg line-clamp-1">{acc.name}</h3>
                    <Bed className="w-5 h-5 text-primary shrink-0" />
                  </div>
                  <div className="flex items-center gap-1 text-sm text-muted-foreground mb-2">
                    <MapPin className="w-4 h-4" />
                    <span className="line-clamp-1">{acc.municipality || acc.location}</span>
                  </div>
                  {acc.rating > 0 && (
                    <div className="flex items-center gap-1 mb-2">
                      <Star className="w-4 h-4 fill-yellow-400 text-yellow-400" />
                      <span className="text-sm font-medium">{acc.rating.toFixed(1)}</span>
                    </div>
                  )}
                  {acc.price_range && (
                    <Badge variant="secondary" className="mb-2">{acc.price_range}</Badge>
                  )}
                  <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
                    {acc.description}
                  </p>
                  <Button
                    variant={addedToItinerary.has(acc.id) ? "secondary" : "default"}
                    size="sm"
                    className="w-full"
                    onClick={(e) => {
                      e.stopPropagation();
                      addToItinerary(acc, 'accommodation');
                    }}
                    disabled={addedToItinerary.has(acc.id)}
                  >
                    {addedToItinerary.has(acc.id) ? (
                      <>
                        <CheckCircle className="w-4 h-4 mr-1" />
                        Added to Itinerary
                      </>
                    ) : (
                      "Add to Itinerary"
                    )}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>
      )}

      {/* Recommended Restaurants */}
      {restaurants.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-3xl font-bold mb-2">Local Dining Spots</h2>
              <p className="text-muted-foreground">Restaurants near your areas of interest</p>
            </div>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {restaurants.map((rest) => (
              <Card key={rest.id} className="hover:shadow-lg transition-shadow">
                <div className="relative h-48 overflow-hidden rounded-t-lg">
                  <img
                    src={rest.image_url || "/placeholder.svg"}
                    alt={rest.name}
                    className="w-full h-full object-cover"
                  />
                </div>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-semibold text-lg line-clamp-1">{rest.name}</h3>
                    <Utensils className="w-5 h-5 text-primary shrink-0" />
                  </div>
                  <div className="flex items-center gap-1 text-sm text-muted-foreground mb-2">
                    <MapPin className="w-4 h-4" />
                    <span className="line-clamp-1">{rest.municipality || rest.location}</span>
                  </div>
                  {rest.food_type && (
                    <Badge variant="secondary" className="mb-2">{rest.food_type}</Badge>
                  )}
                  <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
                    {rest.description}
                  </p>
                  <Button
                    variant={addedToItinerary.has(rest.id) ? "secondary" : "default"}
                    size="sm"
                    className="w-full"
                    onClick={(e) => {
                      e.stopPropagation();
                      addToItinerary(rest, 'restaurant');
                    }}
                    disabled={addedToItinerary.has(rest.id)}
                  >
                    {addedToItinerary.has(rest.id) ? (
                      <>
                        <CheckCircle className="w-4 h-4 mr-1" />
                        Added to Itinerary
                      </>
                    ) : (
                      "Add to Itinerary"
                    )}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>
      )}

      {/* Empty State */}
      {spots.length === 0 && accommodations.length === 0 && restaurants.length === 0 && (
        <Card>
          <CardHeader>
            <CardTitle>No personalized content yet</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground mb-4">
              We couldn't find content matching your preferences. Try exploring all destinations or updating your preferences.
            </p>
            <Button onClick={() => navigate("/explore")}>
              Explore All Destinations
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default PersonalizedFeed;

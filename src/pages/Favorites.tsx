import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Heart, MapPin, Trash2, Loader2 } from "lucide-react";
import Navbar from "@/components/Navbar";

interface FavoriteItem {
  id: string;
  item_id: string;
  item_type: string;
  created_at: string;
  item_details?: any;
}

export default function Favorites() {
  const navigate = useNavigate();
  const [favorites, setFavorites] = useState<FavoriteItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("all");
  const [userId, setUserId] = useState<string | null>(null);

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    if (userId) {
      fetchFavorites();
    }
  }, [userId]);

  const checkAuth = async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      navigate('/auth');
      return;
    }
    setUserId(session.user.id);
  };

  const fetchFavorites = async () => {
    if (!userId) return;

    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('favorites')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false });

      if (error) throw error;

      // Fetch details for each favorite
      const favoritesWithDetails = await Promise.all(
        (data || []).map(async (fav) => {
          let details = null;
          
          if (fav.item_type === 'spot') {
            const { data: spotData } = await supabase
              .from('tourist_spots')
              .select('*')
              .eq('id', fav.item_id)
              .single();
            details = spotData;
          } else if (fav.item_type === 'restaurant') {
            const { data: restaurantData } = await supabase
              .from('restaurants')
              .select('*')
              .eq('id', fav.item_id)
              .single();
            details = restaurantData;
          } else if (fav.item_type === 'event') {
            const { data: eventData } = await supabase
              .from('events')
              .select('*')
              .eq('id', fav.item_id)
              .single();
            details = eventData;
          } else if (fav.item_type === 'accommodation') {
            const { data: accommodationData } = await supabase
              .from('accommodations')
              .select('*')
              .eq('id', fav.item_id)
              .single();
            details = accommodationData;
          }

          return { ...fav, item_details: details };
        })
      );

      setFavorites(favoritesWithDetails);
    } catch (error) {
      console.error('Error fetching favorites:', error);
      toast.error('Failed to load favorites');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveFavorite = async (favoriteId: string) => {
    try {
      const { error } = await supabase
        .from('favorites')
        .delete()
        .eq('id', favoriteId);

      if (error) throw error;

      setFavorites(favorites.filter(fav => fav.id !== favoriteId));
      toast.success('Removed from favorites ❤️');
    } catch (error) {
      console.error('Error removing favorite:', error);
      toast.error('Failed to remove favorite');
    }
  };

  const filteredFavorites = activeTab === 'all' 
    ? favorites 
    : favorites.filter(fav => fav.item_type === activeTab);

  const renderFavoriteCard = (favorite: FavoriteItem) => {
    const item = favorite.item_details;
    if (!item) return null;

    return (
      <Card key={favorite.id} className="overflow-hidden hover:shadow-lg transition-shadow animate-fade-in">
        {item.image_url && (
          <div className="aspect-video w-full overflow-hidden">
            <img
              src={item.image_url}
              alt={item.name}
              className="w-full h-full object-cover hover:scale-105 transition-transform duration-300"
            />
          </div>
        )}
        <CardHeader>
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1">
              <CardTitle className="text-lg">{item.name}</CardTitle>
              <CardDescription className="flex items-center gap-1 mt-1">
                <MapPin className="h-3 w-3" />
                {item.location || item.municipality}
              </CardDescription>
            </div>
            <Badge variant="secondary" className="capitalize">
              {favorite.item_type}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4 line-clamp-2">
            {item.description}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              className="flex-1"
              onClick={() => {
                if (favorite.item_type === 'spot') {
                  navigate(`/spot/${item.id}`);
                } else {
                  navigate('/explore');
                }
              }}
            >
              View Details
            </Button>
            <Button
              variant="destructive"
              size="icon"
              onClick={() => handleRemoveFavorite(favorite.id)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <div className="container mx-auto px-4 py-8 mt-16">
        <div className="mb-8 text-center">
          <h1 className="text-4xl font-bold mb-2 flex items-center justify-center gap-2">
            <Heart className="h-8 w-8 fill-red-500 text-red-500" />
            My Favorites
          </h1>
          <p className="text-muted-foreground">
            Your saved destinations and experiences in Albay
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5 mb-8">
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value="spot">Spots</TabsTrigger>
            <TabsTrigger value="restaurant">Restaurants</TabsTrigger>
            <TabsTrigger value="event">Events</TabsTrigger>
            <TabsTrigger value="accommodation">Hotels</TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab}>
            {loading ? (
              <div className="flex justify-center items-center py-12">
                <Loader2 className="h-8 w-8 animate-spin" />
              </div>
            ) : filteredFavorites.length === 0 ? (
              <Card className="p-12 text-center">
                <div className="text-6xl mb-4">💔</div>
                <h3 className="text-xl font-semibold mb-2">No favorites yet</h3>
                <p className="text-muted-foreground mb-6">
                  Start exploring and save your favorite places!
                </p>
                <Button onClick={() => navigate('/explore')}>
                  Explore Destinations
                </Button>
              </Card>
            ) : (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredFavorites.map(renderFavoriteCard)}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

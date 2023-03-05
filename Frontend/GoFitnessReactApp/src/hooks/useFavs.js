import { getUserFavsWorkoutService } from "../services/services";
import { useContext, useState } from "react";
import { useEffect } from "react";
import { UserAuthContext } from "../context/UserAuthContext";

const useFavs = () => {
  const { userAuth } = useContext(UserAuthContext);
  const token = userAuth.token;

  const [favs, setFavs] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadFavs = async () => {
      try {
        const data = await getUserFavsWorkoutService({ token });

        setFavs(data);
      } catch (error) {
        setError(error.message);
      }
    };

    loadFavs();
  }, [token, setFavs]);

  const addFavs = (fav) => {
    setFavs([fav, ...favs]);
  };

  return { favs, addFavs };
};

export default useFavs;
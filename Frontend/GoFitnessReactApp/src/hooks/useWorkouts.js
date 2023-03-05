import {
  getUserFavsWorkoutService,
  getWorkoutsService,
} from "../services/services";
import { useContext, useState } from "react";
import { useEffect } from "react";
import { UserAuthContext } from "../context/UserAuthContext";

const useWorkouts = ({ value, showFav, filterType, filterMuscleGroup }) => {
  const { userAuth } = useContext(UserAuthContext);
  const token = userAuth.token;
  const idUser = userAuth.userId;

  const [workouts, setWorkouts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadWorkouts = async () => {
      try {
        setLoading(true);

        let data;

        if (!showFav) {
          data = await getWorkoutsService({
            token,
            value,
            filterType,
            filterMuscleGroup,
          });
        } else {
          data = await getUserFavsWorkoutService({ token, idUser });

          console.log(data);
        }

        setWorkouts(data);
      } catch (error) {
        setError(error.message);
      } finally {
        setLoading(false);
      }
    };

    loadWorkouts();
  }, [
    token,
    setWorkouts,
    value,
    showFav,
    idUser,
    filterType,
    filterMuscleGroup,
  ]);

  const addWorkout = (workout) => {
    setWorkouts([workout, ...workouts]);
  };

  const removeWorkout = (id) => {
    setWorkouts(workouts.filter((workout) => workout.id !== id));
  };

  const editWorkout = ({ idWorkout, editedWorkout }) => {
    setWorkouts(
      workouts.map((workout) => {
        console.log(editedWorkout + " dentro del map");
        if (workout.id === idWorkout) {
          workout.name = editedWorkout.name ? editedWorkout.name : workout.name;
          workout.type = editedWorkout.type ? editedWorkout.type : workout.type;
          workout.description = editedWorkout.description
            ? editedWorkout.description
            : workout.description;
          workout.muscle_group = editedWorkout.muscle_group
            ? editedWorkout.muscle_group
            : workout.muscle_group;
        }

        return workout;
      })
    );
  };

  const setWorkoutLikes = ({ workoutId, likes, likeMode }) => {
    setWorkouts(
      workouts.map((workout) => {
        if (workout.id === workoutId) {
          workout.likes = likes;
          workout.userLike = likeMode ? 1 : 0;
        }

        return workout;
      })
    );
  };

  const setWorkoutFavs = ({ workoutId, favs, favMode }) => {
    setWorkouts(
      workouts.map((workout) => {
        if (workout.id === workoutId) {
          workout.favs = favs;
          workout.userFav = favMode ? 1 : 0;
        }

        return workout;
      })
    );
  };

  return {
    workouts,
    loading,
    error,
    addWorkout,
    removeWorkout,
    setWorkoutLikes,
    editWorkout,
    setWorkoutFavs,
  };
};

export default useWorkouts;
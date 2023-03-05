import { useContext, useState } from "react";
import { UserAuthContext } from "../context/UserAuthContext";

import {
  deleteWorkoutService,
  dislikeWorkoutService,
  favWorkoutService,
  likeWorkoutService,
  quitfavWorkoutService,
} from "../services/services";
import { EditExerciseModal } from "./EditExerciseModal";

export const ExerciseCardButtons = ({
  workout,
  removeWorkout,
  setWorkoutLikes,
  editWorkout,
  setWorkoutFavs,
}) => {
  const [stateEditModal, setStateEditModal] = useState(false);

  const { userAuth } = useContext(UserAuthContext);
  const token = userAuth.token;
  const id = workout.id;

  const edit = require("../../src/icons/edit-icon.png");
  const star = require("../../src/icons/bx-fav-icon.png");
  const starFull = require("../../src/icons/bxs-fav-icon.png");
  const heart = require("../../src/icons/bx-like-icon.png");
  const heartFull = require("../../src/icons/bxs-like-icon.png");
  const quit = require("../../src/icons/bx-del-icon.png");

  const HandleDeleteWorkoutClick = async () => {
    try {
      console.log(id);

      await deleteWorkoutService({ id, token });

      removeWorkout(id);
    } catch (error) {
      console.log(error);
    }
  };

  const HandleFavClick = async (favMode) => {
    try {
      let response;

      if (favMode) {
        response = await favWorkoutService({ id, token });
      } else {
        response = await quitfavWorkoutService({ id, token });
      }
      
      setWorkoutFavs({ workoutId: id, favs: response, favMode });
    } catch (error) {
      console.error(error);
    }
  };

  const HandleLikeClick = async (likeMode) => {
    try {
      let response;

      if (likeMode) {
        response = await likeWorkoutService({ id, token });
      } else {
        response = await dislikeWorkoutService({ id, token });
      }

      setWorkoutLikes({ workoutId: id, likes: response, likeMode });
    } catch (error) {
      console.error(error);
    }
  };

  return userAuth.userRole === 1 ? (
    <>
       <EditExerciseModal
        workout={workout}
        stateEditModal={stateEditModal}
        setStateEditModal={setStateEditModal}
        editWorkout={editWorkout}
      />
    <ul className="button-list">
      <li className="card-btn-container">
        <button 
          className="card-button"
          onClick={() => setStateEditModal(!stateEditModal)}
        >
          <img className="card-button-icon" src={edit} alt="" />
        </button>
      </li>
      <li className="card-btn-container">
        <button className="card-button" onClick={HandleDeleteWorkoutClick}>
          <img className="card-button-icon" src={quit} alt="" />
        </button>
      </li>
      </ul>
    </>
  ) : (
    <ul className="button-list">
      <li className="card-btn-container">
        <button
          className="card-button"
          onClick={() => {
            if (workout.userFav) {
              HandleFavClick(false);
            } else {
              HandleFavClick(true);
            }
          }}
        >
          <img
            className="card-button-icon"
            src={workout.userFav ? starFull : star}
            alt=""
          />
        </button>
      </li>
      <li className="card-btn-container">
        <button
          className="card-button"
          onClick={() => {
            if (workout.userLike) {
              HandleLikeClick(false);
            } else {
              HandleLikeClick(true);
            }
          }}
        >
          {workout.likes}
          <img
            className="card-button-icon"
            src={workout.userLike ? heartFull : heart}
            alt=""
          />
        </button>
        {/* {error ? <p>{error}</p> : null} */}
      </li>
    </ul>
  );
};

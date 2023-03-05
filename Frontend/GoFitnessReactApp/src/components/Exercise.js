import { ExerciseCardButtons } from "./ExerciseCardButtons";

export const Exercise = ({
  workout,
  likes,
  addLike,
  removeWorkout,
  setWorkoutLikes,
  editWorkout,
  setWorkoutFavs,
}) => {
  //const video = require ("../../src/video-icon.png");

  return (
    <ul className="exercise-data-list">
      <li className="data-list-item">
        <h2>{workout.name}</h2>
      </li>
      <li className="data-list-item">
        <h3>Tipo: {workout.type}</h3>
      </li>
      <li className="data-list-item">
        <h3>
          Descripción:<p>{workout.description}</p>
        </h3>
      </li>
      <li className="data-list-item">
        <h3>Grupo muscular: {workout.muscle_group}</h3>
      </li>
      <ExerciseCardButtons
        workout={workout}
        likes={likes}
        addLike={addLike}
        removeWorkout={removeWorkout}
        setWorkoutLikes={setWorkoutLikes}
        editWorkout={editWorkout}
        setWorkoutFavs={setWorkoutFavs}
      />
    </ul>
  );
};


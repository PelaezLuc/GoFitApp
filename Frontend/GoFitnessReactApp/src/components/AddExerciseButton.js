import { useContext } from "react";
import { UserAuthContext } from "../context/UserAuthContext";

export const AddExerciseButton = ({ stateAddModal, setStateAddModal }) => {
  const { userAuth } = useContext(UserAuthContext);

  return userAuth.userRole === 1 ? (
    <button
      className="add-exercise-btn"
      onClick={() => setStateAddModal(!stateAddModal)}
    >
      + Añadir ejercicio
    </button>
  ) : null;
};
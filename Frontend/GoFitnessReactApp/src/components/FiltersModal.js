import { useState } from "react";
import "./css/filterModal.css"

export const FiltersModal = ({
  showFiltersModal,
  setShowFiltersModal,
  setFilterType,
  setFilterMuscleGroup,
}) => {
  const handleRebootFilter = () => {
    setFilterType("");
    setFilterMuscleGroup("");

    setShowFiltersModal(false);
  };

  return (
    <>
      {showFiltersModal && (
        <div className="overlay-filter-modal"onClick={(e)=>{
          if (
                      !e.target.closest(".modal-filter-container")
                    ) {
                      setShowFiltersModal(false);
                    }
      }}>
          <div className="modal-filter-container">
            <div className="modal-filter-header">
              <h2 className="title-filter-modal">Filtros</h2>
            </div>
            <form className="modal-filter-form">
              <select
                name="Type"
                onChange={(e) => setFilterType(e.target.value)}
                className ="select"
              >
                <option defaultValue={""} value="">Todos</option>
                <option value="Hipertrofia">Hipertrofia</option>
                <option value="Cardio">Cardio</option>
              </select>
              
              <label htmlFor="filter-controls"></label>

              <input
                className="filter-controls"
                type="text"
                name="muscle-group"
                id="muscle-group"
                placeholder="Grupo muscular"
                onChange={(e) => setFilterMuscleGroup(e.target.value)}
              />

              <button className="reset-filter-btn" onClick={handleRebootFilter}>
                Reiniciar Filtros
              </button> 
            </form>
          </div>
        </div>
      )}
    </>
  );
};
